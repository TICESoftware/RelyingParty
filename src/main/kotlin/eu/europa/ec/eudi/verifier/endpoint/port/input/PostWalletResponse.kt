/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.port.input

import COSE.AlgorithmID
import arrow.core.None
import arrow.core.Option
import arrow.core.raise.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.some
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.sdjwt.*
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Jwt
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.ListElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.doc.MDocVerificationParams
import id.walt.mdoc.doc.VerificationType
import id.walt.mdoc.doc.and
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import software.tice.VpTokenFormat
import software.tice.ZKPVerifier
import java.time.Clock
import java.util.Base64

/**
 * Represent the Authorisation Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: String? = null,
    val presentationSubmission: PresentationSubmission? = null,
)

sealed interface AuthorisationResponse {

    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val state: String?, val jarm: Jwt) : AuthorisationResponse
}

sealed interface WalletResponseValidationError {
    data object InvalidMdoc : WalletResponseValidationError
    data object InvalidFormat : WalletResponseValidationError
    data object InvalidVPToken : WalletResponseValidationError
    data object InvalidSDJwt : WalletResponseValidationError
    data object MissingState : WalletResponseValidationError
    data class PresentationDefinitionNotFound(val requestId: RequestId) : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data class PresentationNotInExpectedState(val requestId: RequestId) : WalletResponseValidationError

    data object IncorrectStateInJarm : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data object MissingVpTokenOrPresentationSubmission : WalletResponseValidationError
}

context(Raise<WalletResponseValidationError>)
internal fun AuthorisationResponseTO.toDomain(presentation: RequestObjectRetrieved): WalletResponse {
    fun requiredIdToken(): WalletResponse.IdToken {
        ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }
        return WalletResponse.IdToken(idToken)
    }

    fun requiredVpToken(): WalletResponse.VpToken {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        ensureNotNull(presentationSubmission) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        return WalletResponse.VpToken(vpToken, presentationSubmission)
    }

    fun requiredIdAndVpToken(): WalletResponse.IdAndVpToken {
        val a = requiredIdToken()
        val b = requiredVpToken()
        return WalletResponse.IdAndVpToken(a.idToken, b.vpToken, b.presentationSubmission)
    }

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }

    return maybeError ?: when (presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().idToken)
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVpToken().vpToken,
            requiredVpToken().presentationSubmission,
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdAndVpToken().idToken,
            requiredIdAndVpToken().vpToken,
            requiredIdAndVpToken().presentationSubmission,
        )
    }
}

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName("redirect_uri") val redirectUri: String,
)

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    suspend operator fun invoke(walletResponse: AuthorisationResponse): Option<WalletResponseAcceptedTO>
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyJarmJwtSignature: VerifyJarmJwtSignature,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val getIssuerEcKey: ECKey,
) : PostWalletResponse {

    private val logger: Logger = LoggerFactory.getLogger(PostWalletResponseLive::class.java)

    context(Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(walletResponse: AuthorisationResponse): Option<WalletResponseAcceptedTO> {
        val presentation = loadPresentation(walletResponse)

        // Verify the AuthorisationResponse matches what is expected for the Presentation
        val responseMode = walletResponse.responseMode()
        ensure(presentation.responseMode == responseMode) {
            WalletResponseValidationError.UnexpectedResponseMode(
                presentation.requestId,
                expected = presentation.responseMode,
                actual = responseMode,
            )
        }

        // generate response depending on response method (DirectPost or DirectPostJwt)
        val responseObject = responseObject(walletResponse, presentation)

        ensureNotNull(responseObject.presentationSubmission?.descriptorMaps) {
            logger.error("Presentation submission missing")
            WalletResponseValidationError.MissingVpTokenOrPresentationSubmission
        }

        // map through the response and call the proper verification methods for every descriptor
        responseObject.presentationSubmission!!.descriptorMaps.map { descriptor ->
            // TODO: ZKPVerifier should be injected via dependency injection
            val verifier = ZKPVerifier(getIssuerEcKey.toECPublicKey())

            val path = descriptor.path.value
            val token = responseObject.vpToken?.let { extractPresentation(it, path) }
            ensureNotNull(token) {
                logger.error("Missing VPToken")
                WalletResponseValidationError.MissingVpTokenOrPresentationSubmission
            }

            when (descriptor.format) {
                "vc+sd-jwt" -> {
                    checkSdJwtSignature(token)
                    logger.info("Successfully verified the sdjwt")
                }

                "mso_mdoc" -> {
                    checkMdocSignature(token)
                    logger.info("Successfully verified the mdoc")
                }

                "vc+sd-jwt+zkp" -> {
                    logger.info("Starting zkp verification for SDJWT")
                    val descriptorId: String = descriptor.id.value

                    val key = presentation.zkpKeys?.get(descriptorId)
                    ensureNotNull(key) { raise(WalletResponseValidationError.InvalidVPToken) }

                    val sdjwtToken = token.split("~")[0]
                    val proofed = sdjwtToken.let {
                        verifier.verifyChallenge(VpTokenFormat.SDJWT, it, key)
                    }
                    ensure(proofed) {
                        raise(WalletResponseValidationError.InvalidVPToken)
                    }
                    logger.info("Proofed SD-JWT with ZK")
                }

                "mso_mdoc+zkp" -> {
                    logger.info("Starting zkp verification for mDoc")
                    val descriptorId: String = descriptor.id.value

                    val key = presentation.zkpKeys?.get(descriptorId)
                    ensureNotNull(key) { raise(WalletResponseValidationError.InvalidVPToken) }

                    // ---

                    val data = DataElement.fromCBOR<MapElement>(Base64.getUrlDecoder().decode(token))
                    val documents = data.value[MapKey("documents")] as? ListElement
                    ensureNotNull(documents) {
                        logger.error("No documents found in MDoc")
                        WalletResponseValidationError.InvalidMdoc
                    }
                    val firstDocument = documents.value[0] as MapElement
                    val firstDoc = Base64.getUrlEncoder().encodeToString(firstDocument.toCBOR())

                    // ---

                    val proofed = firstDoc.let {
                        verifier.verifyChallenge(VpTokenFormat.MSOMDOC, it, key)
                    }
                    ensure(proofed) {
                        raise(WalletResponseValidationError.InvalidVPToken)
                    }
                    logger.info("Proofed MDOC with ZK")
                }

                else -> {
                    logger.error("Unknown format in descriptor path: ${descriptor.path}")
                    raise(WalletResponseValidationError.InvalidFormat)
                }
            }
        }

        // for this use case (let frontend display the submitted data) we store the wallet response
        // Put wallet response into presentation object and store into db
        val submitted = submit(presentation, responseObject).also { storePresentation(it) }

        return when (
            val getWalletResponseMethod = presentation.getWalletResponseMethod
        ) {
            is GetWalletResponseMethod.Redirect -> with(createQueryWalletResponseRedirectUri) {
                requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                WalletResponseAcceptedTO(redirectUri.toExternalForm()).some()
            }

            GetWalletResponseMethod.Poll -> None
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(walletResponse: AuthorisationResponse): RequestObjectRetrieved {
        val state = when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response.state
            is AuthorisationResponse.DirectPostJwt -> walletResponse.state
        }
        ensureNotNull(state) { WalletResponseValidationError.MissingState }
        val requestId = RequestId(state)

        val presentation = loadPresentationByRequestId(requestId)

        ensureNotNull(presentation) { WalletResponseValidationError.PresentationDefinitionNotFound(requestId) }
        ensure(presentation is RequestObjectRetrieved) {
            WalletResponseValidationError.PresentationNotInExpectedState(
                requestId,
            )
        }
        return presentation
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun checkSdJwtSignature(sdJwt: String): SdJwt.Presentation<JwtAndClaims> {
        try {
            val jwtSignatureVerifier = ECDSAVerifier(getIssuerEcKey).asJwtVerifier()

            // TODO: Replace with SdJwtVcVerifier to verify the KeyBinding
            return SdJwtVerifier.verifyPresentation(
                jwtSignatureVerifier = jwtSignatureVerifier,
                keyBindingVerifier = KeyBindingVerifier.MustBePresent,
                unverifiedSdJwt = sdJwt,
            ).getOrThrow()
        } catch (e: SdJwtVerificationException) {
            logger.error("SD-JWT Verification failed: ${e.reason}", e)
            raise(WalletResponseValidationError.InvalidSDJwt)
        } catch (e: Exception) {
            logger.error("Unexpected error during SD-JWT Verification: ${e.message}", e)
            raise(WalletResponseValidationError.InvalidSDJwt)
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun checkMdocSignature(mdoc: String) {
        val data = DataElement.fromCBOR<MapElement>(Base64.getUrlDecoder().decode(mdoc))
        val documents = data.value[MapKey("documents")] as? ListElement
        ensureNotNull(documents) {
            logger.error("No documents found in MDoc")
            WalletResponseValidationError.InvalidMdoc
        }
        val firstDocument = documents.value[0] as MapElement
        val firstMDoc = MDoc.fromMapElement(firstDocument)

        val issuerKeyId = "SPRIND Funke EUDI Wallet Prototype Issuer"
        val cryptoProvider = SimpleCOSECryptoProvider(
            listOf(
                COSECryptoProviderKeyInfo(issuerKeyId, AlgorithmID.ECDSA_256, getIssuerEcKey.toECPublicKey(), null),
            ),
        )

        ensure(
            firstMDoc.verify(
                MDocVerificationParams(
                    VerificationType.ISSUER_SIGNATURE and VerificationType.VALIDITY and VerificationType.DOC_TYPE,
                    issuerKeyId,
                ),
                cryptoProvider,
            ),
        ) {
            logger.error("MDoc verification failed")
            WalletResponseValidationError.InvalidMdoc
        }
    }

    context(Raise<WalletResponseValidationError>)
    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO = when (walletResponse) {
        is AuthorisationResponse.DirectPost -> walletResponse.response
        is AuthorisationResponse.DirectPostJwt -> {
            val response = verifyJarmJwtSignature(
                jarmOption = verifierConfig.clientMetaData.jarmOption,
                ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                jarmJwt = walletResponse.jarm,
            ).getOrThrow()
            ensure(response.state == walletResponse.state) { WalletResponseValidationError.IncorrectStateInJarm }
            response
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Presentation.Submitted {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation)
        val responseCode = when (presentation.getWalletResponseMethod) {
            GetWalletResponseMethod.Poll -> null
            is GetWalletResponseMethod.Redirect -> generateResponseCode()
        }
        return presentation.submit(clock, walletResponse, responseCode).getOrThrow()
    }
}

/**
 * Gets the [ResponseModeOption] that corresponds to the receiver [AuthorisationResponse].
 */
private fun AuthorisationResponse.responseMode(): ResponseModeOption = when (this) {
    is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
    is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
}
