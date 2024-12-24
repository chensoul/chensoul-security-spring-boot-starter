package com.chensoul.security.mfa.provider;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        property = "providerType")
@JsonSubTypes({
	@Type(name = "TOTP", value = TotpMfaProviderConfig.class),
	@Type(name = "SMS", value = SmsMfaProviderConfig.class),
	@Type(name = "EMAIL", value = EmailMfaProviderConfig.class),
	@Type(name = "BACKUP_CODE", value = BackupCodeMfaProviderConfig.class)
})
public interface MfaProviderConfig {

    @JsonIgnore
    MfaProviderType getProviderType();

}
