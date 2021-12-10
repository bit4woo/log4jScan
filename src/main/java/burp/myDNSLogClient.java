package burp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * 一个DNSlog对象，用于存储interactionID和server
 */
public class myDNSLogClient implements IBurpCollaboratorClientContext{
	
	private String rootDomain;
	private String apiToken;

	public myDNSLogClient(String rootDomain, String apitoken) {
		this.rootDomain = rootDomain.trim();
		this.apiToken = apitoken;
	}

	@Override
	public String generatePayload(boolean includeCollaboratorServerLocation) {
		SimpleDateFormat simpleDateFormat = 
				new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS");//毫秒级别
		String timeStr = simpleDateFormat.format(new Date());
        String resultString;
		try {
			 MessageDigest md = MessageDigest.getInstance("MD5");
			 resultString = md.digest(timeStr.getBytes()).toString();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			resultString = timeStr;
		}
		
		if (includeCollaboratorServerLocation) {
			return resultString+"."+rootDomain;
		}else {
			return resultString;
		}
        
	}

	@Override
	public List<IBurpCollaboratorInteraction> fetchAllCollaboratorInteractions() {
		String queryUrl = "http://admin.0y0.fun/apiquery/{logtype}/{subdomain}/{apitoken}/";
		return null;
	}

	@Override
	public List<IBurpCollaboratorInteraction> fetchCollaboratorInteractionsFor(String payload) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IBurpCollaboratorInteraction> fetchAllInfiltratorInteractions() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<IBurpCollaboratorInteraction> fetchInfiltratorInteractionsFor(String payload) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getCollaboratorServerLocation() {
		// TODO Auto-generated method stub
		return null;
	}
	
	
}
