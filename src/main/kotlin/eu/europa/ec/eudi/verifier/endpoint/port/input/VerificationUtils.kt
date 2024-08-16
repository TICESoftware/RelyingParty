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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import org.slf4j.Logger
import org.slf4j.LoggerFactory

fun extractPresentation(vpToken: String, path: String): String? {
    val logger: Logger = LoggerFactory.getLogger(PostWalletResponseLive::class.java)

    if (path == "$") {
        return vpToken
    }

    val jsonElement = Json.parseToJsonElement(vpToken)
    if (jsonElement is JsonArray) {
        val index = path.trim('$', '[', ']').toIntOrNull()
        if (index != null && index in jsonElement.indices) {
            return jsonElement[index].toString().trim('"')
        }
    }
    logger.info("VPToken has wrong format")
    return null
}
