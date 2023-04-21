package eu.europa.ec.euidw.verifier.application.port.out.jose

import eu.europa.ec.euidw.verifier.domain.Jwt

/**
 * An out port that signs a [RequestObject] in form of a [Jwt]
 */
fun interface SignRequestObject {
    operator fun invoke(requestObject: RequestObject): Result<Jwt>
}