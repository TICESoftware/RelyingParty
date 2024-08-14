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

import arrow.core.raise.Raise
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.awaitBody
import software.tice.ChallengeRequestData
import software.tice.ZKPVerifier

sealed interface ZkpJwkError {
    data class ProcessingError(val message: String, val error: Throwable) : ZkpJwkError
}

data class ChallengeRequest(
    val id: String,
    val digest: String,
    val r: String,
    val proofType: String,
)

data class EphemeralKeyResponse(
    val id: String,
    val kid: String,
    val kty: String,
    val crv: String,
    val x: String,
    val y: String,
)


/**
 * Given a [RequestId] and [ServerRequest] returns a list of ephemeral public keys derived from the input data (digest and r) for the ZKP.
 */

fun interface PostZkpJwkRequest {
    context(Raise<ZkpJwkError>)
    suspend operator fun invoke(request: ServerRequest, requestId: RequestId): List<EphemeralKeyResponse>
}

class PostZkpJwkRequestLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val getIssuerEcKey: ECKey
) : PostZkpJwkRequest {

    context(Raise<ZkpJwkError>)
    override suspend operator fun invoke(request: ServerRequest, requestId: RequestId): List<EphemeralKeyResponse> {
        val verifier = ZKPVerifier(getIssuerEcKey.toECPublicKey())
        val presentation = loadPresentationByRequestId(requestId)

        val challengeRequests = request.awaitBody<Array<ChallengeRequest>>()

        return challengeRequests.map { challengeRequest ->
            val challengeRequestData = ChallengeRequestData(digest = challengeRequest.digest, r = challengeRequest.r)
            val (challenge, key) = verifier.createChallenge(challengeRequestData)

            val x = challenge.w.affineX.toString()
            val y = challenge.w.affineY.toString()

            if (presentation is Presentation.Submitted) {
                val zkpStateResult = Presentation.ZkpState.zkpReady(presentation, key)
                zkpStateResult.onSuccess { zkpState ->
                    storePresentation(zkpState)
                }.onFailure { error ->
                    raise(ZkpJwkError.ProcessingError("Failed to create ZkpState", error))
                }
            }

            EphemeralKeyResponse(
                id = challengeRequest.id,
                kid = challengeRequest.id,
                kty = "EC",
                crv = "P-256",
                x = x,
                y = y,
            )
        }
    }
}
