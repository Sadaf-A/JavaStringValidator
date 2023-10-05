package org.validate.validate;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;
import org.json.JSONTokener;

public class Validate {
    /**
     * Checks if an object is a string.
     *
     * @param obj The object to check.
     * @return true if the object is a string, false otherwise.
     */
    public static boolean isString(Object obj) {
        return obj instanceof String;
    }
    /**
     * Checks if an object is of type boolean.
     *
     * @param obj The object to check.
     * @return true if the object is of type boolean, false otherwise.
     */
    public static boolean isBoolean(Object obj) {
        return obj instanceof Boolean;
    }
    /**
     * Checks if an object is of type Number.
     *
     * @param obj The object to check.
     * @return true if the object is of type Number, false otherwise.
     */
    public static boolean isNumber(Object obj) {
        return obj instanceof Number;
    }
    /**
     * Checks if a string is a valid regular expression pattern.
     *
     * @param regex The string to check as a regular expression.
     * @return true if the string is a valid regular expression, false otherwise.
     */
    public static boolean isValidRegExp(String regex) {
        try {
            // Attempt to compile the string as a regular expression.
            Pattern.compile(regex);
            return true; // If no exception is thrown, it's a valid RegExp.
        } catch (PatternSyntaxException e) {
            return false; // If an exception is thrown, it's not a valid RegExp.
        }
    }
    /**
     * Checks if a string is a valid UUID.
     *
     * @param uuidStr The string to check as a UUID.
     * @return true if the string is a valid UUID, false otherwise.
     */
    public static boolean isValidUUID(String uuidStr) {
        try {
            // Attempt to parse the string as a UUID.
            UUID uuid = UUID.fromString(uuidStr);
            return true; // If no exception is thrown, it's a valid UUID.
        } catch (IllegalArgumentException e) {
            return false; // If an exception is thrown, it's not a valid UUID.
        }
    }
    /**
     * Checks if a string represents a valid Semantic Version (SemVer).
     *
     * @param versionStr The string to check as a SemVer version.
     * @return true if the string is a valid SemVer version, false otherwise.
     */
    public static boolean isSemVer(String versionStr) {
        if (versionStr == null || versionStr.isEmpty()) {
            return false; // Empty or null strings are not valid SemVer versions.
        }

        String[] parts = versionStr.split("-");
        if (parts.length > 2) {
            return false; // SemVer versions can have at most two parts (major.minor.patch and optional pre-release).
        }

        String[] versionParts = parts[0].split("\\.");
        if (versionParts.length != 3) {
            return false; // SemVer versions consist of three parts: major.minor.patch.
        }

        try {
            int major = Integer.parseInt(versionParts[0]);
            int minor = Integer.parseInt(versionParts[1]);
            int patch = Integer.parseInt(versionParts[2]);

            if (major < 0 || minor < 0 || patch < 0) {
                return false; // Negative numbers are not allowed.
            }

            return true; // If no exceptions are thrown, it's a valid SemVer version.
        } catch (NumberFormatException e) {
            return false; // Parsing as integers failed, not a valid SemVer version.
        }
    }
    /**
     * Checks if a string represents a valid email address.
     *
     * @param emailStr The string to check as an email address.
     * @return true if the string is a valid email address, false otherwise.
     */
    public static boolean isValidEmail(String emailStr) {
        if (emailStr == null || emailStr.isEmpty()) {
            return false; // Empty or null strings are not valid email addresses.
        }

        // Regular expression pattern for a basic email address validation.
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";

        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(emailStr);

        return matcher.matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a string represents a valid mobile phone number.
     *
     * @param phoneNumberStr The string to check as a mobile phone number.
     * @return true if the string is a valid mobile phone number, false otherwise.
     */
    public static boolean isValidMobilePhoneNumber(String phoneNumberStr) {
        if (phoneNumberStr == null || phoneNumberStr.isEmpty()) {
            return false; // Empty or null strings are not valid phone numbers.
        }

        // Regular expression pattern for a basic mobile phone number validation.
        // This pattern matches numeric strings of 10 or more digits.
        String phoneRegex = "^[0-9]{10,}$";

        Pattern pattern = Pattern.compile(phoneRegex);
        Matcher matcher = pattern.matcher(phoneNumberStr);

        return matcher.matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a string represents a valid locale.
     *
     * @param localeStr The string to check as a locale.
     * @return true if the string is a valid locale, false otherwise.
     */
    public static boolean isValidLocale(String localeStr) {
        if (localeStr == null || localeStr.isEmpty()) {
            return false; // Empty or null strings are not valid locales.
        }

        String[] parts = localeStr.split("_");
        if (parts.length != 2) {
            return false; // Locales should consist of language and country parts.
        }

        String language = parts[0];
        String country = parts[1];

        // Validate the language and country parts.
        if (!isValidLanguage(language) || !isValidCountry(country)) {
            return false;
        }

        return true;
    }
    /**
     * Checks if a string represents a valid language code.
     *
     * @param language The language code to check.
     * @return true if the language code is valid, false otherwise.
     */
    private static boolean isValidLanguage(String language) {
        // You can add additional checks for valid language codes here if needed.
        // For simplicity, let's assume all non-empty strings are valid languages.
        return !language.isEmpty();
    }
    /**
     * Checks if a string represents a valid country code.
     *
     * @param country The country code to check.
     * @return true if the country code is a valid ISO 3166-1 alpha-2 code, false otherwise.
     */
    private static boolean isValidCountry(String country) {
        if (country == null || country.isEmpty()) {
            return false; // Empty or null country codes are not valid.
        }

        // Check if the country code consists of two uppercase letters.
        if (!country.matches("^[A-Z]{2}$")) {
            return false;
        }

        // You can add more specific checks for valid country codes here if needed.

        return true;
    }
    /**
     * Checks if a string represents valid latitude and longitude values.
     *
     * @param latLongStr The string to check as a latitude and longitude pair.
     * @return true if the string is a valid latitude and longitude pair, false otherwise.
     */
    public static boolean isValidLatLong(String latLongStr) {
        if (latLongStr == null || latLongStr.isEmpty()) {
            return false; // Empty or null strings are not valid.
        }

        // Split the input into latitude and longitude parts.
        String[] parts = latLongStr.split(",");
        if (parts.length != 2) {
            return false; // A valid lat-long pair should have exactly two parts.
        }

        try {
            // Parse latitude and longitude as doubles.
            double latitude = Double.parseDouble(parts[0]);
            double longitude = Double.parseDouble(parts[1]);

            // Check valid latitude and longitude ranges.
            if (latitude < -90.0 || latitude > 90.0 || longitude < -180.0 || longitude > 180.0) {
                return false; // Values out of range are not valid.
            }

            return true; // If no exceptions are thrown, it's a valid lat-long pair.
        } catch (NumberFormatException e) {
            return false; // Parsing as doubles failed, not a valid lat-long pair.
        }
    }
    /**
     * Checks if a string represents a valid color in hexadecimal, HSL, or RGB format.
     *
     * @param colorStr The string to check as a color value.
     * @return true if the string is a valid color value, false otherwise.
     */
    public static boolean isValidColor(String colorStr) {
        if (colorStr == null || colorStr.isEmpty()) {
            return false; // Empty or null strings are not valid colors.
        }

        // Check if it's a valid hexadecimal color (e.g., #RRGGBB or #RGB).
        if (colorStr.matches("^#([A-Fa-f0-9]{3}){1,2}$")) {
            return true;
        }

        // Check if it's a valid HSL color (e.g., hsl(h, s%, l%)).
        if (colorStr.matches("^hsl\\(\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+%\\s*,\\s*\\d+%\\s*\\)$")) {
            return true;
        }

        // Check if it's a valid RGB color (e.g., rgb(r, g, b) or rgba(r, g, b, a)).
        if (colorStr.matches("^rgb\\(\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+(\\.\\d+)?\\s*\\)$") ||
                colorStr.matches("^rgba\\(\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+(\\.\\d+)?\\s*,\\s*\\d+(\\.\\d+)?\\s*\\)$")) {
            return true;
        }

        return false; // If none of the formats match, it's not a valid color.
    }
    /**
     * Checks if a string represents a valid IPv4 address.
     *
     * @param ipAddressStr The string to check as an IPv4 address.
     * @return true if the string is a valid IPv4 address, false otherwise.
     */
    public static boolean isValidIPv4(String ipAddressStr) {
        if (ipAddressStr == null || ipAddressStr.isEmpty()) {
            return false; // Empty or null strings are not valid IPv4 addresses.
        }

        // Regular expression pattern for a valid IPv4 address.
        String ipv4Regex = "^(?:(25[0-5]|(?:2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$";

        Pattern pattern = Pattern.compile(ipv4Regex);

        return pattern.matcher(ipAddressStr).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a string represents a valid IPv6 address.
     *
     * @param ipAddressStr The string to check as an IPv6 address.
     * @return true if the string is a valid IPv6 address, false otherwise.
     */
    public static boolean isValidIPv6(String ipAddressStr) {
        if (ipAddressStr == null || ipAddressStr.isEmpty()) {
            return false; // Empty or null strings are not valid IPv6 addresses.
        }

        // Regular expression pattern for a valid IPv6 address.
        String ipv6Regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))";

        Pattern pattern = Pattern.compile(ipv6Regex);

        return pattern.matcher(ipAddressStr).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid Fully Qualified Domain Name (FQDN).
     * This function uses a regular expression to validate whether the input string
     * conforms to the FQDN format. A valid FQDN typically consists of letters (both
     * uppercase and lowercase), digits, hyphens, and dots, with at least two letters
     * at the end (e.g., ".com," ".org").
     *
     * @param domain The string to check as an FQDN.
     * @return true if the string is a valid FQDN, false otherwise.
     */
    public static boolean isValidFQDN(String domain) {
        if (domain == null || domain.isEmpty()) {
            return false; // Empty or null strings are not valid FQDNs.
        }

        // Regular expression pattern for a valid FQDN.
        String fqdnRegex = "^(?i)([a-zA-Z0-9-]+\\.)*[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}$";

        Pattern pattern = Pattern.compile(fqdnRegex);

        return pattern.matcher(domain).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid URL.
     * This function validates whether the input string conforms to the URL format.
     * A valid URL typically consists of a scheme (e.g., "http" or "https"), followed
     * by "://" and a valid domain name or IP address. It may also include a path,
     * query parameters, and a fragment identifier.
     *
     * @param urlString The string to check as a URL.
     * @return true if the string is a valid URL, false otherwise.
     */
    public static boolean isValidURL(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false; // Empty or null strings are not valid URLs.
        }

        // Regular expression pattern for a valid URL.
        String urlRegex = "^(https?|ftp)://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9./?%&=]*)?$";

        Pattern pattern = Pattern.compile(urlRegex);

        return pattern.matcher(urlString).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid connection string.
     * This function validates whether the input string conforms to the connection string
     * format.
     *
     * @param connectionString The string to check as a connection string.
     * @return true if the string is a valid connection string, false otherwise.
     */
    public static boolean isValidConnectionString(String connectionString) {
        if (connectionString == null || connectionString.isEmpty()) {
            return false; // Empty or null strings are not valid connection strings.
        }

        connectionString = connectionString.replace(":", "-");
        // Regular expression pattern for a valid connection string.
        // This pattern allows for an optional "user:password@" part before the hostname or IP address and port.
        String connectionRegex = "^(?:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+@)?[A-Za-z0-9.-]+(:[0-9]+)?(/[^?#\\s]*)?(?:[?]([^#\\s]+))?$";

        return connectionString.matches(connectionRegex);
    }

    /**
     * Checks if a given string represents a valid hexadecimal value.
     *
     * This function validates whether the input string is a valid hexadecimal value.
     * A valid hexadecimal value consists of digits (0-9) and/or letters (A-F or a-f)
     * and may optionally start with "0x" or "0X" to denote a hexadecimal prefix.
     *
     * @param hexString The string to check as a hexadecimal value.
     * @return true if the string is a valid hexadecimal value, false otherwise.
     */
    public static boolean isValidHexadecimal(String hexString) {
        if (hexString == null || hexString.isEmpty()) {
            return false; // Empty or null strings are not valid hexadecimal values.
        }

        // Regular expression pattern for a valid hexadecimal value.
        String hexRegex = "^(0[xX])?[0-9A-Fa-f]+$";

        Pattern pattern = Pattern.compile(hexRegex);

        return pattern.matcher(hexString).matches(); // Returns true if the string matches the pattern.
    }

    /**
     * Checks if a given string represents a valid MD5 hash.
     * This function validates whether the input string conforms to the MD5 hash format,
     * which consists of 32 hexadecimal characters (0-9, a-f).
     *
     * @param md5Hash The string to check as an MD5 hash.
     * @return true if the string is a valid MD5 hash, false otherwise.
     */
    public static boolean isValidMD5Hash(String md5Hash) {
        if (md5Hash == null || md5Hash.isEmpty()) {
            return false; // Empty or null strings are not valid MD5 hashes.
        }

        // Regular expression pattern for a valid MD5 hash.
        String md5Regex = "^[0-9a-fA-F]{32}$";

        Pattern pattern = Pattern.compile(md5Regex);

        return pattern.matcher(md5Hash).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid hash using SHA-1, SHA-256, SHA-384, or SHA-512.
     * This function validates whether the input string conforms to the hash format of
     * SHA-1, SHA-256, SHA-384, or SHA-512, which consist of hexadecimal characters (0-9, a-f).
     *
     * @param hashValue The string to check as a SHA hash.
     * @return true if the string is a valid SHA hash, false otherwise.
     */
    public static boolean isValidSHAHash(String hashValue) {
        if (hashValue == null || hashValue.isEmpty()) {
            return false; // Empty or null strings are not valid SHA hashes.
        }

        // Regular expression pattern for valid SHA-1, SHA-256, SHA-384, or SHA-512 hashes.
        String shaRegex = "^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$|^[0-9a-fA-F]{96}$|^[0-9a-fA-F]{128}$";

        Pattern pattern = Pattern.compile(shaRegex);

        return pattern.matcher(hashValue).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid country code using ISO 3166-1 alpha-2 or alpha-3 codes.
     *
     * This function validates whether the input string is a valid country code based on
     * the ISO 3166-1 standard. It supports both alpha-2 (e.g., "US") and alpha-3 (e.g., "USA")
     * country codes.
     *
     * @param countryCode The string to check as a country code.
     * @return true if the string is a valid ISO 3166-1 alpha-2 or alpha-3 country code, false otherwise.
     */
    public static boolean isValidISO3166CountryCode(String countryCode) {
        if (countryCode == null || countryCode.isEmpty()) {
            return false; // Empty or null strings are not valid country codes.
        }

        // Regular expression pattern for valid ISO 3166-1 alpha-2 or alpha-3 country codes.
        String iso3166Regex = "^[A-Za-z]{2}$|^[A-Za-z]{3}$";

        return countryCode.matches(iso3166Regex); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid currency code using ISO 4217.
     *
     * This function validates whether the input string is a valid currency code based on
     * the ISO 4217 standard. ISO 4217 currency codes consist of three uppercase letters.
     *
     * @param currencyCode The string to check as a currency code.
     * @return true if the string is a valid ISO 4217 currency code, false otherwise.
     */
    public static boolean isValidISO4217CurrencyCode(String currencyCode) {
        if (currencyCode == null || currencyCode.isEmpty()) {
            return false; // Empty or null strings are not valid currency codes.
        }

        // Regular expression pattern for valid ISO 4217 currency codes.
        String iso4217Regex = "^[A-Z]{3}$";

        return currencyCode.matches(iso4217Regex); // Returns true if the string matches the pattern.
    }

    /**
     * Checks if a given string represents a valid Docker image name or repository.
     *
     * This function validates whether the input string conforms to the Docker image name
     * or repository format. It allows lowercase letters, digits, hyphens, periods, and
     * colons in the image name, and it supports optional namespace and tag.
     *
     * @param dockerImage The string to check as a Docker image name or repository.
     * @return true if the string is a valid Docker image name or repository, false otherwise.
     */
    public static boolean isValidDockerImage(String dockerImage) {
        if (dockerImage == null || dockerImage.isEmpty()) {
            return false; // Empty or null strings are not valid Docker image names/repositories.
        }

        // Regular expression pattern for a valid Docker image name or repository.
        String dockerImageRegex = "^((?:[a-z0-9]([-a-z0-9]*[a-z0-9])?\\.)+[a-z]{2,6}(?::\\d{1,5})?/)?[a-z0-9]+(?:[._\\-/:][a-z0-9]+)*$";

        Pattern pattern = Pattern.compile(dockerImageRegex, Pattern.MULTILINE);

        return pattern.matcher(dockerImage).find(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid Amazon Resource Name (ARN).
     * This function validates whether the input string conforms to the Amazon Resource Name (ARN)
     * format. ARNs have a specific structure with colon-separated components, such as AWS service,
     * region, account ID, resource type, and resource name.
     *
     * @param arn The string to check as an ARN.
     * @return true if the string is a valid ARN, false otherwise.
     */
    public static boolean isValidARN(String arn) {
        if (arn == null || arn.isEmpty()) {
            return false; // Empty or null strings are not valid ARNs.
        }

        // Regular expression pattern for a valid Amazon Resource Name (ARN).
        String arnRegex = "^arn:([^:\\n]+):([^:\\n]+):(?:[^:\\n]*):(?:([^:\\n]*)):([^:/\\n]+)(?:(:[^\\n]+)|(\\//[^:\\n]+))?$";

        Pattern pattern = Pattern.compile(arnRegex, Pattern.MULTILINE);

        return pattern.matcher(arn).find(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid MAC address.
     *
     * This function validates whether the input string conforms to the MAC address format.
     * A valid MAC address is a 12-character hexadecimal string, typically separated by colons
     * or hyphens (e.g., "00:1A:2B:3C:4D:5E" or "00-1A-2B-3C-4D-5E").
     *
     * @param macAddress The string to check as a MAC address.
     * @return true if the string is a valid MAC address, false otherwise.
     */
    public static boolean isValidMACAddress(String macAddress) {
        if (macAddress == null || macAddress.isEmpty()) {
            return false; // Empty or null strings are not valid MAC addresses.
        }

        // Regular expression pattern for a valid MAC address.
        String macRegex = "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$";

        Pattern pattern = Pattern.compile(macRegex);

        return pattern.matcher(macAddress).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid MIME type.
     *
     * This function validates whether the input string conforms to the MIME type format,
     * which typically consists of a type and a subtype separated by a forward slash
     * (e.g., "text/plain" or "image/jpeg"). It allows for optional parameters following
     * the subtype.
     *
     * @param mimeType The string to check as a MIME type.
     * @return true if the string is a valid MIME type, false otherwise.
     */
    public static boolean isValidMIMEType(String mimeType) {
        if (mimeType == null || mimeType.isEmpty()) {
            return false; // Empty or null strings are not valid MIME types.
        }

        // Regular expression pattern for a valid MIME type.
        String mimeRegex = "^[a-zA-Z]+/[a-zA-Z]+([+-_.][a-zA-Z0-9]+)*$";

        Pattern pattern = Pattern.compile(mimeRegex);

        return pattern.matcher(mimeType).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid MongoDB ObjectId (MongoId).
     *
     * This function validates whether the input string conforms to the MongoDB ObjectId format.
     * A valid MongoDB ObjectId is a 24-character hexadecimal string.
     *
     * @param mongoId The string to check as a MongoDB ObjectId.
     * @return true if the string is a valid MongoDB ObjectId, false otherwise.
     */
    public static boolean isValidMongoId(String mongoId) {
        if (mongoId == null || mongoId.isEmpty()) {
            return false; // Empty or null strings are not valid MongoDB ObjectIds.
        }

        // Regular expression pattern for a valid MongoDB ObjectId.
        String mongoIdRegex = "^[0-9a-fA-F]{24}$";

        Pattern pattern = Pattern.compile(mongoIdRegex);

        return pattern.matcher(mongoId).matches(); // Returns true if the string matches the pattern.
    }
    /**
     * Checks if a given string represents a valid AWS Region.
     *
     * This function validates whether the input string is a valid AWS Region.
     *
     * @param awsRegion The string to check as an AWS Region.
     * @return true if the string is a valid AWS Region, false otherwise.
     */
    public static boolean isValidAWSRegion(String awsRegion) {
        if (awsRegion == null || awsRegion.isEmpty()) {
            return false; // Empty or null strings are not valid AWS Regions.
        }

        Set<String> awsRegions = new HashSet<>(Set.of(
                "af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
                "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ca-central-1", "cn-north-1",
                "cn-northwest-1", "eu-central-1", "eu-north-1", "eu-south-1", "eu-west-1",
                "eu-west-2", "eu-west-3", "me-south-1", "sa-east-1", "us-east-1", "us-east-2",
                "us-gov-east-1", "us-gov-west-1", "us-west-1", "us-west-2"));

        return awsRegions.contains(awsRegion);
    }
    /**
     * Checks if a given string represents a valid Azure Region.
     *
     * This function validates whether the input string is a valid Azure Region.
     *
     * @param azureRegion The string to check as an Azure Region.
     * @return true if the string is a valid Azure Region, false otherwise.
     */
    public static boolean isValidAzureRegion(String azureRegion) {
        if (azureRegion == null || azureRegion.isEmpty()) {
            return false; // Empty or null strings are not valid Azure Regions.
        }

        Set<String> azureRegions = new HashSet<>(Set.of(
                "eastus", "eastus2", "centralus", "northcentralus", "southcentralus",
                "westcentralus", "westus", "westus2", "canadacentral", "canadaeast",
                "brazilsouth", "brazilsoutheast", "northeurope", "westeurope", "uksouth",
                "ukwest", "francecentral", "francesouth", "switzerlandnorth", "switzerlandwest",
                "germanywestcentral", "norwayeast", "norwaywest", "eastasia", "southeastasia",
                "australiaeast", "australiasoutheast", "australiacentral", "australiacentral2",
                "japaneast", "japanwest", "koreacentral", "koreasouth", "southafricanorth",
                "southafricawest", "uaenorth", "uaecentral", "usgovarizona", "usgovtexas",
                "usdodeast", "usdodcentral", "usgovvirginia", "usgoviowa", "usgovcalifornia",
                "ussecwest", "usseceast"));

        return azureRegions.contains(azureRegion);
    }
    /**
     * Checks if a given string represents a valid GCP Region.
     *
     * This function validates whether the input string is a valid GCP Region.
     *
     * @param gcpRegion The string to check as a GCP Region.
     * @return true if the string is a valid GCP Region, false otherwise.
     */
    public static boolean isValidGCPRegion(String gcpRegion) {
        if (gcpRegion == null || gcpRegion.isEmpty()) {
            return false; // Empty or null strings are not valid GCP Regions.
        }

        Set<String> gcpRegions = new HashSet<>(Set.of(
                "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-central1",
                "northamerica-northeast1", "southamerica-east1", "europe-north1", "europe-west1",
                "europe-west2", "europe-west3", "europe-west4", "europe-west6", "asia-east1",
                "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
                "asia-south1", "asia-southeast1", "australia-southeast1", "australiasoutheast2",
                "southasia-east1", "northamerica-northeast2", "europe-central2", "asia-southeast2",
                "asia-east3", "europe-west7", "us-west4", "europe-west8", "asia-northeast4",
                "asia-southeast3", "us-west5", "us-central2", "us-east5", "us-north1",
                "northamerica-northeast3", "us-west6"));

        return gcpRegions.contains(gcpRegion);
    }
    /**
     * Checks if a given string represents a valid Oracle Cloud Region.
     *
     * This function validates whether the input string is a valid Oracle Cloud Region.
     *
     * @param oracleRegion The string to check as an Oracle Cloud Region.
     * @return true if the string is a valid Oracle Cloud Region, false otherwise.
     */
    public static boolean isValidOracleRegion(String oracleRegion) {
        if (oracleRegion == null || oracleRegion.isEmpty()) {
            return false; // Empty or null strings are not valid Oracle Cloud Regions.
        }

        Set<String> oracleRegions = new HashSet<>(Set.of(
                "us-ashburn-1", "us-phoenix-1", "ca-toronto-1", "sa-saopaulo-1", "uk-london-1",
                "uk-gov-london-1", "eu-frankfurt-1", "eu-zurich-1", "eu-amsterdam-1", "me-jeddah-1",
                "ap-mumbai-1", "ap-osaka-1", "ap-seoul-1", "ap-sydney-1", "ap-tokyo-1",
                "ap-chuncheon-1", "ap-melbourne-1", "ap-hyderabad-1", "ca-montreal-1", "us-sanjose-1",
                "us-luke-1", "me-dubai-1", "us-gov-ashburn-1", "us-gov-chicago-1", "us-gov-phoenix-1",
                "us-gov-orlando-1", "us-gov-sanjose-1", "us-gov-ashburn-2"));

        return oracleRegions.contains(oracleRegion);
    }
    /**
     * Checks if a given string represents a valid IBM Cloud Region.
     *
     * This function validates whether the input string is a valid IBM Cloud Region.
     *
     * @param ibmRegion The string to check as an IBM Cloud Region.
     * @return true if the string is a valid IBM Cloud Region, false otherwise.
     */
    public static boolean isValidIBMRegion(String ibmRegion) {
        if (ibmRegion == null || ibmRegion.isEmpty()) {
            return false; // Empty or null strings are not valid IBM Cloud Regions.
        }

        Set<String> ibmRegions = new HashSet<>(Set.of(
                "us-south", "us-east", "us-north", "us-west", "eu-gb", "eu-de", "eu-nl", "eu-fr",
                "eu-it", "ap-north", "ap-south", "ap-east", "ap-jp", "ap-au", "ca-toronto", "ca-central",
                "sa-saopaulo", "sa-mexico", "sa-buenosaires", "sa-lima", "sa-santiago", "af-za",
                "af-eg", "af-dz", "af-ma"));

        return ibmRegions.contains(ibmRegion);
    }
    /**
     * Checks if a given string represents a valid Alibaba Cloud Region.
     *
     * This function validates whether the input string is a valid Alibaba Cloud Region.
     *
     * @param alibabaRegion The string to check as an Alibaba Cloud Region.
     * @return true if the string is a valid Alibaba Cloud Region, false otherwise.
     */
    public static boolean isValidAlibabaRegion(String alibabaRegion) {
        if (alibabaRegion == null || alibabaRegion.isEmpty()) {
            return false; // Empty or null strings are not valid Alibaba Cloud Regions.
        }

        Set<String> alibabaRegions = new HashSet<>(Set.of(
                "cn-hangzhou", "cn-shanghai", "cn-beijing", "cn-shenzhen", "cn-zhangjiakou",
                "cn-huhehaote", "cn-wulanchabu", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
                "ap-southeast-5", "ap-northeast-1", "ap-south-1", "ap-south-2", "us-west-1",
                "us-east-1", "eu-west-1", "eu-central-1", "me-east-1", "ap-southwest-1"));

        return alibabaRegions.contains(alibabaRegion);
    }
    /**
     * Checks if a given string represents a valid ISO 639-1 language code.
     * This function validates whether the input string conforms to the ISO 639-1 language code format.
     * ISO 639-1 language codes consist of two lowercase letters.
     *
     * @param languageCode The string to check as an ISO 639-1 language code.
     * @return true if the string is a valid ISO 639-1 language code, false otherwise.
     */
    public static boolean isValidISO6391LanguageCode(String languageCode) {
        if (languageCode == null || languageCode.isEmpty()) {
            return false; // Empty or null strings are not valid ISO 639-1 language codes.
        }

        // Regular expression pattern for valid ISO 639-1 language codes.
        String iso6391Regex = "^[a-z]{2}$";

        return iso6391Regex.matches(languageCode); // Returns true if the string matches the pattern.
    }

    /**
     * Checks if a given string represents a valid date and time.
     *
     * This function validates whether the input string conforms to the date and time format.
     * It checks if the string is a valid date, a valid time, or a valid combination of date and time.
     *
     * @param dateTimeStr The string to check as a date and time.
     * @return true if the string is a valid date and time, false otherwise.
     */
    public static boolean isValidDateTime(String dateTimeStr) {
        if (dateTimeStr == null || dateTimeStr.isEmpty()) {
            return false; // Empty or null strings are not valid date and time.
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

        try {
            Date date = dateFormat.parse(dateTimeStr);
            return true; // If parsing is successful, it's a valid date and time.
        } catch (ParseException e) {
            return false; // Parsing failed, not a valid date and time.
        }
    }
    /**
     * Checks if a given JSON string conforms to a JSON schema.
     *
     * This function validates whether the input JSON string conforms to the specified JSON schema.
     * It uses the `org.everit.json.schema` library to perform the validation.
     *
     * @param jsonStr The JSON string to validate.
     * @param jsonSchemaStr The JSON schema as a string.
     * @return true if the JSON string conforms to the schema, false otherwise.
     */
    public static boolean isValidJSONWithSchema(String jsonStr, String jsonSchemaStr) {
        try {
            JSONObject jsonSchema = new JSONObject(new JSONTokener(jsonSchemaStr));
            JSONObject jsonObject = new JSONObject(new JSONTokener(jsonStr));

            Schema schema = SchemaLoader.load(jsonSchema);

            schema.validate(jsonObject);

            return true; // Validation successful, JSON conforms to the schema.
        } catch (Exception e) {
            return false; // Validation failed, JSON does not conform to the schema.
        }
    }
}

