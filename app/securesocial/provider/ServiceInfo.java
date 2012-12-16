/**
 * 
 */
package securesocial.provider;

import java.io.Serializable;

import play.libs.OAuth;

/**
 * @author chriswebb
 *
 */
public class ServiceInfo implements Serializable {
	private static final long serialVersionUID = 4923285634028350602L;
	
	public String requestTokenURL;
    public String accessTokenURL;
    public String authorizationURL;
    public String consumerKey;
    public String consumerSecret;
    
    /**
     * @param requestTokenURL
     * @param accessTokenURL
     * @param authorizationURL
     * @param consumerKey
     * @param consumerSecret
     */
    public ServiceInfo(String requestTokenURL,
                        String accessTokenURL,
                        String authorizationURL,
                        String consumerKey,
                        String consumerSecret) {
        this.requestTokenURL = requestTokenURL;
        this.accessTokenURL = accessTokenURL;
        this.authorizationURL = authorizationURL;
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
    }
    
    /**
     * @param oauthInfo
     */
    public ServiceInfo(OAuth.ServiceInfo oauthInfo) {
    	super();
    	copyFrom(oauthInfo);	
    }
    
    /**
     * @param aouthInfo
     */
    public void copyFrom(OAuth.ServiceInfo aouthInfo) {
        this.requestTokenURL = aouthInfo.requestTokenURL;
        this.accessTokenURL = aouthInfo.accessTokenURL;
        this.authorizationURL = aouthInfo.authorizationURL;
        this.consumerKey = aouthInfo.consumerKey;
        this.consumerSecret = aouthInfo.consumerSecret;
    }
    
    /**
     * @param aouthInfo
     */
    public void copyTo(SocialUser socialUser) {
    	if (socialUser.serviceInfo == null) {
    		socialUser.serviceInfo = new OAuth.ServiceInfo(this.requestTokenURL, this.accessTokenURL, this.authorizationURL, this.consumerKey, this.consumerSecret);
    	} else {
    		socialUser.serviceInfo.requestTokenURL = this.requestTokenURL;
    		socialUser.serviceInfo.accessTokenURL = this.accessTokenURL;
    		socialUser.serviceInfo.authorizationURL = this.authorizationURL;
    		socialUser.serviceInfo.consumerKey = this.consumerKey;
    		socialUser.serviceInfo.consumerSecret = this.consumerSecret;
    	}
    }
}
