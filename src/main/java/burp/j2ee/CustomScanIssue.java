package burp.j2ee;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private Risk severity;
    private String remedy;
    private Confidence confidence = Confidence.Certain;
    private String interactionID;//DNSlog的扫描需要的字段
    private long sendTime;//DNSlog的扫描需要的字段
    
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String remedy,
            Risk severity,
            Confidence confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remedy = remedy;
        this.severity = severity;
        this.confidence = confidence;
    }
    
    /**
     * 使用了DNSlog的issue和未使用DNSlog的issue可以使用同一个类
     * @param httpService
     * @param url
     * @param httpMessages
     * @param name
     * @param detail
     * @param remedy
     * @param severity
     * @param confidence
     * @param interactionID
     * @param sendTime
     */
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String remedy,
            Risk severity,
            Confidence confidence,
            String interactionID,
            long sendTime) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remedy = remedy;
        this.severity = severity;
        this.confidence = confidence;
        this.interactionID = interactionID;
        this.sendTime = sendTime;
    }  
    
    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String remedy,
            Risk severity,
            Confidence confidence,
            String interactionID) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remedy = remedy;
        this.severity = severity;
        this.confidence = confidence;
        this.interactionID = interactionID;
        this.sendTime = System.currentTimeMillis();
    }  

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return severity.toString();
    }

    @Override
    // "Certain", "Firm" or "Tentative"
    public String getConfidence() {
        return confidence.toString();
    }

    public String getInteractionID() {
		return interactionID;
	}

	public long getSendTime() {
		return sendTime;
	}

	@Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }
    
    public void setIssueDetail(String detail) {
        this.detail =  detail;
    }

    @Override
    public String getRemediationDetail() {
        return remedy;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
    
}
