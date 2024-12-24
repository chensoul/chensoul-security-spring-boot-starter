package com.chensoul.security.mfa.config;

import com.chensoul.security.mfa.provider.MfaProviderType;
import com.fasterxml.jackson.annotation.JsonGetter;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import javax.validation.constraints.NotBlank;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class BackupCodeMfaConfig extends MfaConfig {

    @NotBlank
    private String codes;

    @Override
    public MfaProviderType getProviderType() {
        return MfaProviderType.BACKUP_CODE;
    }

    @JsonGetter("codes")
    public Set<String> getCodesForJson() {
        if (serializeHiddenFields) {
            return new TreeSet<>(Arrays.asList(codes.split(",")));
        } else {
            return null;
        }
    }

    @JsonGetter
    private Integer getCodesLeft() {
        if (codes!=null) {
            return getCodesForJson().size();
        } else {
            return null;
        }
    }

}
