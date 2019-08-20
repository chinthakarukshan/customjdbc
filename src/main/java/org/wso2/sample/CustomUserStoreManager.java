package org.wso2.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.utils.Secret;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

/**
 * @author Chinthaka Weerakkody
 */
public class CustomUserStoreManager extends JDBCUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);

    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
        log.info("CustomUserStoreManager initialized...");
    }

    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        boolean isAuthenticated = false;
        if (userName != null && credential != null) {

            try {
                String candidatePassword = String.copyValueOf(((Secret)credential).getChars());

                StringBuilder hash = new StringBuilder();

                MessageDigest sha = MessageDigest.getInstance("SHA-1");
                byte[] hashedBytes = sha.digest(candidatePassword.getBytes());
                char[] digits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'a', 'b', 'c', 'd', 'e', 'f' };
                for (int idx = 0; idx < hashedBytes.length; ++idx) {
                    byte b = hashedBytes[idx];
                    hash.append(digits[(b & 0xf0) >> 4]);
                    hash.append(digits[b & 0x0f]);
                }

                String hashedPassword = hash.toString();

                log.info("####PASSWORD#### Hashed Password : " + hashedPassword);

                Connection dbConnection = null;
                ResultSet rs = null;
                PreparedStatement prepStmt = null;
                String sql = null;

                dbConnection = this.getDBConnection();

                dbConnection.setAutoCommit(false);

                sql = this.realmConfig.getUserStoreProperty("SelectUserSQL");
                if (log.isDebugEnabled()) {
                    log.debug(sql);
                }

                prepStmt = dbConnection.prepareStatement(sql);
                prepStmt.setString(1, userName);


                rs = prepStmt.executeQuery();
                if (rs.next()) {
                    String storedPassword = rs.getString(2);

                    if (storedPassword.equals(hashedPassword)) {
                        isAuthenticated = true;
                    }
                }

            } catch (SQLException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return isAuthenticated;
    }
}
