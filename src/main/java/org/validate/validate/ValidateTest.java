package org.validate.validate;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ValidateTest {

    @Test
    public void testIsString() {
        assertTrue(Validate.isString("Hello, World!"));
        assertFalse(Validate.isString(42));
        assertFalse(Validate.isString(true));
        assertFalse(Validate.isString(null));
    }

    @Test
    public void testIsBoolean() {
        assertTrue(Validate.isBoolean(true));
        assertTrue(Validate.isBoolean(false));
        assertFalse(Validate.isBoolean(42));
        assertFalse(Validate.isBoolean("true"));
        assertFalse(Validate.isBoolean(null));
    }

    @Test
    public void testIsNumber() {
        assertTrue(Validate.isNumber(42));
        assertTrue(Validate.isNumber(3.14));
        assertFalse(Validate.isNumber("42"));
        assertFalse(Validate.isNumber(true));
        assertFalse(Validate.isNumber(null));
    }

    @Test
    public void testIsValidRegExp() {
        assertTrue(Validate.isValidRegExp("^\\d{3}$"));
        assertFalse(Validate.isValidRegExp("[a-z"));
    }

    @Test
    public void testIsValidUUID() {
        assertTrue(Validate.isValidUUID("550e8400-e29b-41d4-a716-446655440000"));
        assertFalse(Validate.isValidUUID("not-a-uuid"));
    }

    @Test
    public void testIsSemVer() {
        assertTrue(Validate.isSemVer("1.2.3"));
        assertTrue(Validate.isSemVer("0.10.0"));
        assertTrue(Validate.isSemVer("3.0.0-beta"));
        assertFalse(Validate.isSemVer("1.2"));
        assertFalse(Validate.isSemVer("1.2.3.4"));
        assertFalse(Validate.isSemVer("-1.2.3"));
        assertFalse(Validate.isSemVer("1.2.-3"));
        assertFalse(Validate.isSemVer(null));
    }
    @Test
    public void testIsValidEmail() {
        assertTrue(Validate.isValidEmail("test@example.com"));
        assertTrue(Validate.isValidEmail("user.name@example.co.uk"));
        assertFalse(Validate.isValidEmail("invalid.email"));
        assertFalse(Validate.isValidEmail(null));
    }

    @Test
    public void testIsValidMobilePhoneNumber() {
        assertTrue(Validate.isValidMobilePhoneNumber("1234567890"));
        assertTrue(Validate.isValidMobilePhoneNumber("5555555555"));
        assertFalse(Validate.isValidMobilePhoneNumber("12345"));
        assertFalse(Validate.isValidMobilePhoneNumber("not-a-phone-number"));
        assertFalse(Validate.isValidMobilePhoneNumber(null));
    }

    @Test
    public void testIsValidLocale() {
        assertTrue(Validate.isValidLocale("en_US"));
        assertTrue(Validate.isValidLocale("fr_FR"));
        assertFalse(Validate.isValidLocale("invalid-locale"));
        assertFalse(Validate.isValidLocale("en"));
        assertFalse(Validate.isValidLocale(null));
    }

    @Test
    public void testIsValidLatLong() {
        assertTrue(Validate.isValidLatLong("34.0522,-118.2437"));
        assertTrue(Validate.isValidLatLong("-90,180"));
        assertFalse(Validate.isValidLatLong("invalid-lat,long"));
        assertFalse(Validate.isValidLatLong("100,200"));
        assertFalse(Validate.isValidLatLong("34.0522,-118.2437,-45.6789"));
        assertFalse(Validate.isValidLatLong(null));
    }
    @Test
    public void testIsValidColor() {
        assertTrue(Validate.isValidColor("#FFA500")); // Valid Hexadecimal Color
        assertTrue(Validate.isValidColor("hsl(120, 100%, 50%)")); // Valid HSL Color
        assertTrue(Validate.isValidColor("rgb(255, 0, 0)")); // Valid RGB Color
        assertFalse(Validate.isValidColor("invalid-color")); // Invalid Color
        assertFalse(Validate.isValidColor(null)); // Null Color
    }

    @Test
    public void testIsValidIPv4() {
        assertTrue(Validate.isValidIPv4("192.168.1.1")); // Valid IPv4 Address
        assertFalse(Validate.isValidIPv4("256.0.0.1")); // Invalid IPv4 Address
        assertFalse(Validate.isValidIPv4("invalid-ip-address")); // Invalid Format
        assertFalse(Validate.isValidIPv4(null)); // Null Address
    }

    @Test
    public void testIsValidIPv6() {
        assertTrue(Validate.isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")); // Valid IPv6 Address
        assertFalse(Validate.isValidIPv6("invalid-ipv6-address")); // Invalid Format
        assertFalse(Validate.isValidIPv6(null)); // Null Address
    }

    @Test
    public void testIsValidFQDN() {
        assertTrue(Validate.isValidFQDN("example.com")); // Valid FQDN
        assertTrue(Validate.isValidFQDN("sub.example.co.uk")); // Valid FQDN with subdomain
        assertFalse(Validate.isValidFQDN("invalid_fqdn")); // Invalid FQDN
        assertFalse(Validate.isValidFQDN(null)); // Null FQDN
    }
    @Test
    public void testIsValidURL() {
        assertTrue(Validate.isValidURL("http://www.example.com")); // Valid URL
        assertTrue(Validate.isValidURL("https://www.example.com/path/to/page")); // Valid HTTPS URL with path
        assertTrue(Validate.isValidURL("ftp://ftp.example.com")); // Valid FTP URL
        assertFalse(Validate.isValidURL("invalid-url")); // Invalid URL
        assertFalse(Validate.isValidURL(null)); // Null URL
    }

    @Test
    public void testIsValidConnectionString() {
        assertTrue(Validate.isValidConnectionString("localhost:8080")); // Valid Connection String without credentials
        assertFalse(Validate.isValidConnectionString(null)); // Null Connection String
    }

    @Test
    public void testIsValidHexadecimal() {
        assertTrue(Validate.isValidHexadecimal("1A2f")); // Valid Hexadecimal
        assertTrue(Validate.isValidHexadecimal("0x1F")); // Valid Hexadecimal with 0x prefix
        assertFalse(Validate.isValidHexadecimal("invalid-hexadecimal")); // Invalid Hexadecimal
        assertFalse(Validate.isValidHexadecimal(null)); // Null Hexadecimal
    }

    @Test
    public void testIsValidMD5Hash() {
        assertTrue(Validate.isValidMD5Hash("d41d8cd98f00b204e9800998ecf8427e")); // Valid MD5 Hash
        assertFalse(Validate.isValidMD5Hash("invalid-md5-hash")); // Invalid MD5 Hash
        assertFalse(Validate.isValidMD5Hash(null)); // Null MD5 Hash
    }

    @Test
    public void testIsValidSHAHash() {
        assertTrue(Validate.isValidSHAHash("5eb63bbbe01eeed093cb22bb8f5acdc3d85c7e5d")); // Valid SHA-1 Hash
        assertTrue(Validate.isValidSHAHash("36d9c2a62c0b71f3b61f063f14a88f9311feadb59af85585b75c45d0739a2bfbc078bf08aeb65fb90f78ed29994a2c54")); // Valid SHA-256 Hash
        assertTrue(Validate.isValidSHAHash("b678a1756071ea35c4f28b06e8a9312c6e28a4418a5b1f98397c72258cd0cbf31ca8d22cf5d49f0635be7804f5f6e19ac5e2594d454f81b882e2ed55f5e51a3b")); // Valid SHA-384 Hash
        assertTrue(Validate.isValidSHAHash("b135c8e51d04e1cc956d6be1179b35d36d74bd8573990ce0d87ecaceae4a4395b76a755c4eb57f74c2d0ec1ca1ea04ef581b1e8dcd34a787f5cfa6ec769a3474")); // Valid SHA-512 Hash
        assertFalse(Validate.isValidSHAHash("invalid-sha-hash")); // Invalid SHA Hash
        assertFalse(Validate.isValidSHAHash(null)); // Null SHA Hash
    }
    @Test
    public void testIsValidISO3166CountryCode() {
        assertTrue(Validate.isValidISO3166CountryCode("US"));
        assertTrue(Validate.isValidISO3166CountryCode("CAN"));
        assertFalse(Validate.isValidISO3166CountryCode(""));
        assertFalse(Validate.isValidISO3166CountryCode("ABCD"));
    }

    @Test
    public void testIsValidISO4217CurrencyCode() {
        assertTrue(Validate.isValidISO4217CurrencyCode("USD"));
        assertTrue(Validate.isValidISO4217CurrencyCode("EUR"));
        assertFalse(Validate.isValidISO4217CurrencyCode(""));
        assertFalse(Validate.isValidISO4217CurrencyCode("ABCD"));
        assertFalse(Validate.isValidISO4217CurrencyCode("US"));
        assertFalse(Validate.isValidISO4217CurrencyCode("US1"));
    }

    @Test
    public void testIsValidDockerImage() {
        assertTrue(Validate.isValidDockerImage("nginx"));
        assertTrue(Validate.isValidDockerImage("my-app:latest"));
        assertTrue(Validate.isValidDockerImage("my-namespace/my-app:1.0"));
        assertFalse(Validate.isValidDockerImage(""));
        assertFalse(Validate.isValidDockerImage("MyApp"));
    }

    @Test
    public void testIsValidARN() {
        assertTrue(Validate.isValidARN("arn:aws:s3:::my-bucket"));
        assertFalse(Validate.isValidARN(""));
        assertFalse(Validate.isValidARN("my-arn"));
        assertFalse(Validate.isValidARN("arn:aws:s3:my-bucket"));
    }

    @Test
    public void testIsValidMACAddress() {
        assertTrue(Validate.isValidMACAddress("00:1A:2B:3C:4D:5E"));
        assertTrue(Validate.isValidMACAddress("00-1A-2B-3C-4D-5E"));
        assertFalse(Validate.isValidMACAddress(""));
        assertFalse(Validate.isValidMACAddress("00:1A:2B:3C:4D:5E:6F"));
        assertFalse(Validate.isValidMACAddress("00:1A:2B:3G:4D:5E"));
    }

    @Test
    public void testIsValidMIMEType() {
        assertTrue(Validate.isValidMIMEType("text/plain"));
        assertTrue(Validate.isValidMIMEType("application/json"));
        assertTrue(Validate.isValidMIMEType("image/jpeg"));
        assertFalse(Validate.isValidMIMEType(""));
        assertFalse(Validate.isValidMIMEType("text-plain"));
    }

    @Test
    public void testIsValidMongoId() {
        assertTrue(Validate.isValidMongoId("5f5b281ad9d63a001f41d372"));
        assertFalse(Validate.isValidMongoId(""));
        assertFalse(Validate.isValidMongoId("5f5b281ad9d63a001f41d3721"));
        assertFalse(Validate.isValidMongoId("5f5b281ad9d63a001f41d37z"));
    }

}
