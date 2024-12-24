package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.MfaProviderType;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.io.Serializable;
import lombok.Data;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(
	use = JsonTypeInfo.Id.NAME,
	property = "providerType")
@JsonSubTypes({
	@Type(name = "TOTP", value = TotpMfaConfig.class),
	@Type(name = "SMS", value = SmsMfaConfig.class),
	@Type(name = "EMAIL", value = EmailMfaConfig.class),
	@Type(name = "BACKUP_CODE", value = BackupCodeMfaConfig.class)
})
@Data
public abstract class MfaConfig implements Serializable {

	private boolean useByDefault;

	@JsonIgnore
	protected transient boolean serializeHiddenFields;

	@JsonIgnore
	public abstract MfaProviderType getProviderType();
}
