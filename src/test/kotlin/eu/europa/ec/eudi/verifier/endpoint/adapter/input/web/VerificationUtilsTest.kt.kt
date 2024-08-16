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
import eu.europa.ec.eudi.verifier.endpoint.port.input.extractPresentation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class VerificationUtilsTest {

    @Test
    fun `extractPresentation should return the SD-JWT from the path`() {
        val sdJwt = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0"
        val vpToken = "[{\"key\": \"value\"}, $sdJwt]"
        val path = "$[1]"

        val result = extractPresentation(vpToken, path)

        assertEquals(sdJwt, result)
    }

    @Test
    fun `extractPresentation should return null for invalid path`() {
        val vpToken = "[{\"key\": \"value1\"}, {\"key\": \"value2\"}]"
        val path = "$[2]"

        val result = extractPresentation(vpToken, path)

        assertNull(result)
    }
}
