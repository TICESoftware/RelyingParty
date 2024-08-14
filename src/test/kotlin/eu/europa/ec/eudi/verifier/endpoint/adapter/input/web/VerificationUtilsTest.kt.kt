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