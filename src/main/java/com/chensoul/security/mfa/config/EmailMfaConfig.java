package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.MfaProviderType;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class EmailMfaConfig extends OtpBasedMfaConfig {

    @NotBlank
    @Email
    private String email;

    @Override
    public MfaProviderType getProviderType() {
        return MfaProviderType.EMAIL;
    }
}
