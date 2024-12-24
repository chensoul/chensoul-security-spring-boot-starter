package com.chensoul.security.mfa;

import com.chensoul.security.jwt.token.JwtPair;
import com.chensoul.security.mfa.provider.MfaProviderType;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/mfa")
@RequiredArgsConstructor
public class MfaAuthController {
    private final MfaSettingService mfaSettingService;

    @PostMapping("/verification/send")
    @PreAuthorize("hasAuthority('PRE_VERIFICATION_TOKEN')")
    public void requestTwoFaVerificationCode() throws Exception {
        mfaSettingService.prepareVerificationCode();
    }

    @PostMapping("/verification/check")
    @PreAuthorize("hasAuthority('PRE_VERIFICATION_TOKEN')")
    public JwtPair checkTwoFaVerificationCode(@RequestParam String verificationCode) throws Exception {
        return mfaSettingService.checkVerificationCode(verificationCode);
    }

    @GetMapping("/providers")
    @PreAuthorize("hasAuthority('PRE_VERIFICATION_TOKEN')")
    public List<TwoFaProviderInfo> getAvailableTwoFaProviders() {
        return mfaSettingService.getAvailableTwoFaProviders();
    }

    @Data
    @AllArgsConstructor
    @Builder
    public static class TwoFaProviderInfo {
        private MfaProviderType type;
        private boolean useByDefault;
        private String contact;
        private Integer minVerificationCodeSendPeriod;
    }

}
