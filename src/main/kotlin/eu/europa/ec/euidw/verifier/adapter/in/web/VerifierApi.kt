package eu.europa.ec.euidw.verifier.adapter.`in`.web

import eu.europa.ec.euidw.verifier.application.port.`in`.*
import eu.europa.ec.euidw.verifier.domain.Nonce
import eu.europa.ec.euidw.verifier.domain.PresentationId
import eu.europa.ec.euidw.verifier.domain.RequestId
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import kotlin.jvm.optionals.getOrNull

class VerifierApi(
    private val initTransaction: InitTransaction,
    private val getWalletResponse: GetWalletResponse
) {

    val route = coRouter {

        POST(
            initTransactionPath,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            this@VerifierApi::handleInitTransaction
        )
        GET(walletResponsePath, accept(APPLICATION_JSON), this@VerifierApi::handleGetWalletResponse)

    }

    private suspend fun handleInitTransaction(req: ServerRequest): ServerResponse {

        suspend fun transactionInitiated(jar: JwtSecuredAuthorizationRequestTO) =
            ok().json().bodyValueAndAwait(jar)

        suspend fun failed(t: Throwable) = when (t) {
            is ValidationException -> badRequest().json().bodyValueAndAwait("error" to t.error)
            else -> badRequest().buildAndAwait()
        }

        val input = req.awaitBody<InitTransactionTO>()

        return initTransaction(input).fold(
            onSuccess = { transactionInitiated(it) },
            onFailure = { failed(it) }
        )
    }

    /**
     * Handles a request placed by verifier, in order to obtain
     * the wallet authorisation response
     */
    private suspend fun handleGetWalletResponse(req: ServerRequest): ServerResponse {

        suspend fun found(walletResponse: WalletResponseTO) = ok().json().bodyValueAndAwait(walletResponse)

        val presentationId = req.presentationId()
        val nonce = req.queryParam("nonce").getOrNull()?.let { Nonce(it) }
        return if (nonce == null) badRequest().buildAndAwait()
        else when (val result = getWalletResponse(presentationId, nonce)) {
            is QueryResponse.NotFound -> ServerResponse.notFound().buildAndAwait()
            is QueryResponse.InvalidState -> badRequest().buildAndAwait()
            is QueryResponse.Found -> found(result.value)
        }

    }

    companion object {
        const val initTransactionPath = "/ui/presentations"
        const val walletResponsePath = "/ui/presentations/{presentationId}"

        /**
         * Extracts from the request the [RequestId]
         */
        private fun ServerRequest.presentationId() = PresentationId(pathVariable("presentationId"))
    }
}