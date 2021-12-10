package burp.j2ee.issues;


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import java.util.List;

public interface IModule {
	//Do request and check the response to identify the issue, need to return IScanIssue object.    
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks,
            IHttpRequestResponse baseRequestResponse, 
            IScannerInsertionPoint insertionPoint);
    
    
    public String getScanLevel();
    //3 level: host url insertpoint
}