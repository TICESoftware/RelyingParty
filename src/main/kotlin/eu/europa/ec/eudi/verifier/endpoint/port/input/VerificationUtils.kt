package eu.europa.ec.eudi.verifier.endpoint.port.input

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import org.slf4j.Logger
import org.slf4j.LoggerFactory

fun extractPresentation(vpToken: String, path: String): String? {
    val logger: Logger = LoggerFactory.getLogger(PostWalletResponseLive::class.java)

    val jsonElement = Json.parseToJsonElement(vpToken)
    if (jsonElement is JsonArray) {
        val index = path.trim('$', '[', ']').toIntOrNull()
        print( index)
        if (index != null && index in jsonElement.indices) {
            return jsonElement[index].toString().trim('"')
        }
    }
    logger.info("VPToken has wrong format")
    return null
}

