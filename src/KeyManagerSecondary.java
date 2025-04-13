import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.sql.Date;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.crypto.SecretKey;

public abstract class KeyManagerSecondary implements KeyManager {

    /*
     * Non-Kernel Methods
     */

    @Override
    public void keyRotation() {
        int size = this.size();
        for (int i = 0; i < size; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            this.keyRetreival(metaData);
            String keyName = metaData.keySet().iterator().next();
            List<String> values = metaData.get(keyName);
            String keyUse = values.get(0);
            String keyAccess = values.get(2);

            this.keyDestruction(keyName);
            this.keyGenerator(keyUse, keyAccess);
            this.keyStorage();
        }

    }

    @Override
    public void exportKeyLog(String fileName) {
        try (BufferedWriter writer = new BufferedWriter(
                new FileWriter(fileName))) {
            for (int i = 0; i < this.size(); i++) {
                Map<String, List<String>> meta = new HashMap<>();

                this.keyRetreival(meta);

                String keyName = meta.keySet().iterator().next();

                writer.write("Key: " + keyName);
                writer.newLine();

                for (Map.Entry<String, List<String>> entry : meta.entrySet()) {
                    String key = entry.getKey();
                    List<String> value = entry.getValue();
                    writer.write("\t" + key + ": " + value);
                    writer.newLine();
                }

                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void cleanupExpiredKeys() {
        for (int i = 0; i < this.size(); i++) {
            Map<String, List<String>> meta = new HashMap<>();
            this.keyRetreival(meta);

            String keyName = meta.keySet().iterator().next();
            List<String> creationDates = meta.get(keyName);

            if (creationDates != null && !creationDates.isEmpty()) {
                String creationDateStr = creationDates.get(1);
                long creationTimestamp = Long.parseLong(creationDateStr);
                Date creationDate = new Date(creationTimestamp);
                Instant creationInstant = creationDate.toInstant();
                Instant oneMonthAgo = Instant.now().minus(30,
                        ChronoUnit.DAYS);
                if (creationInstant.isBefore(oneMonthAgo)) {
                    this.keyDestruction(keyName);
                }
            }
        }
    }

    @Override
    public List<String> findKeysByAccess(String access) {
        int size = this.size();
        List<String> accessibleKeys = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            this.keyRetreival(metaData);
            String keyName = metaData.keySet().iterator().next();
            List<String> values = metaData.get(keyName);
            String accessKey = values.get(2);
            if (accessKey.equals(
                    access)) {
                accessibleKeys.add(keyName);
            }
        }
        return accessibleKeys;
    }

    @Override
    public boolean verifyKeySignatures(PublicKey publicKey) {
        int size = this.size();
        boolean verifyKeys = false;
        for (int i = 0; i < size; i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            this.keyRetreival(metaData);
            String keyName = metaData.keySet().iterator().next();
            List<String> values = metaData.get(keyName);
            String signatureString = values.get(3);

            byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
            try {
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initVerify(publicKey);
                signature.update(keyName.getBytes(StandardCharsets.UTF_8));
                if (signature.verify(signatureBytes)) {
                    verifyKeys = true;
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        return verifyKeys;
    }

    @Override
    public int hashCode() {
    Set<String> keyNames = new HashSet<>();
    for (int i = 0; i < this.size(); i++) {
        Map<String, List<String>> metaData = new HashMap<>();
        this.keyRetreival(metaData);
        keyNames.addAll(metaData.keySet());
    }
    return Objects.hash(keyNames);
}

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        List<String> keyNames = new ArrayList<>();
        for (int i = 0; i < this.size(); i++) {
            Map<String, List<String>> metaData = new HashMap<>();
            this.keyRetreival(metaData);
            keyNames.addAll(metaData.keySet());
        }
        sb.append(String.join(", ", keyNames));
        return sb.toString();
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj){
            return true;
        }
        if (obj == null || getClass() != obj.getClass()){
            return false;
        }
    
        KeyManager other = (KeyManager) obj;

    
    Set<String> thisKeyNames = new HashSet<>();
    for (int i = 0; i < this.size(); i++) {
        Map<String, List<String>> metaData = new HashMap<>();
        this.keyRetreival(metaData);
        thisKeyNames.addAll(metaData.keySet());
    }
    
    Set<String> otherKeyNames = new HashSet<>();
    for (int i = 0; i < other.size(); i++) {
        Map<String, List<String>> metaData = new HashMap<>();
        other.keyRetreival(metaData);
        otherKeyNames.addAll(metaData.keySet());
    }

    return thisKeyNames.equals(otherKeyNames);
    }
}
