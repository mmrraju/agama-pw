package org.gluu.agama.pw;

import org.gluu.agama.pw.jans.JansPasswordService;

import java.util.HashMap;
import java.util.Map;

public abstract class PasswordService {

    public abstract boolean passwordPolicyMatch(String userPassword);

    public abstract Map<String, String> getUserEntityByMail(String email);

    public abstract String sendEmail(String to);

    public abstract String updateUserPassword(String userPassword, String mail);

    public abstract boolean validate(String username, String password);

    public abstract String lockAccount(String username);

    public static PasswordService getInstance(HashMap config) {
        return new JansPasswordService(config);
    }
}
