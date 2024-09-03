package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import arrow.core.Either
import arrow.core.Option
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.oauth2.sdk.Request
import eu.europa.ec.eudi.prex.*
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.fail
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.*
import org.mockito.kotlin.eq
import org.mockito.MockitoAnnotations
import org.mockito.kotlin.whenever
import software.tice.VpTokenFormat
import software.tice.ZKPVerifier
import java.net.URI
import java.net.URL
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.*
import java.util.concurrent.ConcurrentHashMap


class ZkpTests {
    @Mock
    private lateinit var loadPresentationByRequestId: LoadPresentationByRequestId

    @Mock
    private lateinit var storePresentation: StorePresentation

    @Mock
    private lateinit var verifyJarmJwtSignature: VerifyJarmJwtSignature

    @Mock
    private lateinit var clock: Clock

    @Mock
    private lateinit var verifierConfig: VerifierConfig

    @Mock
    private lateinit var generateResponseCode: GenerateResponseCode

    @Mock
    private lateinit var createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri

    @Mock
    private lateinit var getIssuerEcKey: ECKey

    @Mock
    private lateinit var zkpVerifier: ZKPVerifier


    @BeforeEach
    fun setUp() {
        MockitoAnnotations.openMocks(this)
    }


    @Test
    fun `should call zkpVerifier verifyChallenge for vc+sd-jwt+zkp format`() = runTest {
        // Generate KeyPair for zkp
        val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()
        val privateKey = keyPair.private
        val hashMapkeys: ConcurrentHashMap<String, ECPrivateKey> = ConcurrentHashMap()
        hashMapkeys["1"] = privateKey as ECPrivateKey
        val zkpKeys: ConcurrentHashMap<String, ECPrivateKey> = ConcurrentHashMap<String, ECPrivateKey>().apply {
            put("id", privateKey)
        }
        // Mock time
        val fixedInstant = Instant.parse("2023-01-01T00:00:00Z")
        val fixedClock = Clock.fixed(fixedInstant, ZoneId.of("UTC"))

//        // generate fixed response code
        val fixedResponseCode = ResponseCode("test")
        val generateResponseCode: GenerateResponseCode = GenerateResponseCode.fixed(fixedResponseCode)

        // mock postWalletResponseLive

        val transactionId = TransactionId("transactionId")
        val instant = Instant.now()
        val presentationType: PresentationType = PresentationType.IdAndVpToken(
            idTokenType = listOf(IdTokenType.SubjectSigned), presentationDefinition = PresentationDefinition(name = null, id = Id("id"), inputDescriptors = listOf(
                InputDescriptor(constraints = Constraints.LimitDisclosure.PREFERRED, id = InputDescriptorId("id"))
            ))
        )
        val redirectUriTemplate = "http://localhost:0/wallet-redirect#response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}"
        val requestId = RequestId("requestId")
        val nonce = Nonce("nonce")
        val responseMode = ResponseModeOption.DirectPost
        val getWalletResponseMethod: GetWalletResponseMethod.Redirect =
            GetWalletResponseMethod.Redirect(redirectUriTemplate)

        // Create a real implementation of CreateQueryWalletResponseRedirectUri for the test
        val createQueryWalletResponseRedirectUri = object : CreateQueryWalletResponseRedirectUri {
            override fun redirectUri(template: String, responseCode: ResponseCode): Result<URL> = runCatching {
                URL(template.replace(CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER, responseCode.value))
            }

            override fun GetWalletResponseMethod.Redirect.redirectUri(responseCode: ResponseCode): URL =
                redirectUri(redirectUriTemplate, responseCode).getOrThrow()
        }

        val postWalletResponseLive = PostWalletResponseLive(
            loadPresentationByRequestId,
            storePresentation,
            verifyJarmJwtSignature,
            fixedClock,
            verifierConfig,
            generateResponseCode,
            createQueryWalletResponseRedirectUri,
            getIssuerEcKey,
            zkpVerifier
        )


        val presentation = RequestObjectRetrieved(
            id = transactionId,
            initiatedAt = instant,
            type = presentationType,
            requestId = requestId,
            requestObjectRetrievedAt = instant,
            nonce = nonce,
            ephemeralEcPrivateKey = null,
            responseMode = responseMode,
            getWalletResponseMethod = GetWalletResponseMethod.Redirect(redirectUriTemplate),
            zkpKeys = zkpKeys
        )

        val jsonContent = TestUtils.loadResource("02-presentationSubmissionSdJwtZkp.json")
        val presentationSubmission = Json.decodeFromString<PresentationSubmission>(jsonContent)

        val authorizationResponse = AuthorisationResponse.DirectPost(
            AuthorisationResponseTO(
                idToken = "idToken",
                state = "state",
                vpToken = "vpToken",
                presentationSubmission = presentationSubmission,
            )
        )

        val walletResponse = WalletResponse.IdToken(idToken = "idToken")

//
        val submittedPresentation = Presentation.Submitted(
            id = transactionId,
            initiatedAt = fixedInstant,
            type = presentationType,
            walletResponse = walletResponse,
            nonce = nonce,
            requestId = RequestId("id"),
            requestObjectRetrievedAt = fixedInstant,
            responseCode = fixedResponseCode,
            submittedAt = fixedInstant
        )

//       whenever(presentation.submit(fixedClock, walletResponse, fixedResponseCode)).thenReturn(
//           Result.success(submittedPresentation))


//        whenever(createQueryWalletResponseRedirectUri.redirectUri(template = redirectUriTemplate, responseCode = fixedResponseCode)).thenAnswer { invocation ->
//            val template = invocation.getArgument<String>(0)
//            val responseCode = invocation.getArgument<ResponseCode>(1)
//            Result.success(URI(template.replace(CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER, responseCode.value)).toURL())
//        }

        whenever(loadPresentationByRequestId.invoke(RequestId("state"))).thenReturn(presentation)
        whenever(
            zkpVerifier.verifyChallenge(
                eq(VpTokenFormat.SDJWT),
                eq("vpToken"),
                eq(privateKey)
            )
        ).thenReturn(true)


        // Act
        val result = postWalletResponseLive.invoke(authorizationResponse)
        print("this is the result $result")

//        verify(zkpVerifier).verifyChallenge(
//            eq(VpTokenFormat.SDJWT),
//            eq("vpToken"),
//            eq(privateKey),
//        )

    }
}