package burp;

import java.io.PrintWriter;
import java.util.List;

import burp.j2ee.CollaboratorThread;
import burp.j2ee.issues.collaimpl.Log4jRCE;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {

	private static PrintWriter stdout;
	private static PrintWriter stderr;
	private static IBurpExtenderCallbacks callbacks;
	private static IExtensionHelpers helpers;

	public static CollaboratorThread Collaborator; //本地的查询dnslog的线程

	public static IBurpCollaboratorClientContext DNSlogClient;

	public static IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	public static IExtensionHelpers getHelpers() {
		return helpers;
	}

	public static String ExtensionName = "log4jScan";
	public static String Version = bsh.This.class.getPackage().getImplementationVersion();
	public static String Author = "by bit4woo";	
	public static String github = "https://github.com/bit4woo/log4jScan";

	//name+version+author
	public static String getFullExtensionName(){
		return ExtensionName+" "+Version+" "+Author;
	}

	public static PrintWriter getStdout() {
		try{
			stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
		}catch (Exception e){
			stdout = new PrintWriter(System.out, true);
		}
		return stdout;
	}

	public static PrintWriter getStderr() {
		try{
			stderr = new PrintWriter(BurpExtender.callbacks.getStderr(), true);
		}catch (Exception e){
			stderr = new PrintWriter(System.out, true);
		}
		return stderr;
	}

	//
	// implement IBurpExtender
	//
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		BurpExtender.helpers = callbacks.getHelpers();

		// obtain our output stream
		stdout = getStdout();
		stderr = getStderr();

		DNSlogClient = callbacks.createBurpCollaboratorClientContext();
		Collaborator = new CollaboratorThread(callbacks,DNSlogClient);//启动dnslog查询线程
		Collaborator.start();

		callbacks.setExtensionName(getFullExtensionName());
		stdout.println(getFullExtensionName());

		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);
		callbacks.registerExtensionStateListener(this);
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		return doScan(baseRequestResponse,insertionPoint);
	}
	
	
	public List<IScanIssue> doScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
		List<IScanIssue> issues = new Log4jRCE().scan(callbacks, baseRequestResponse, insertionPoint);
		if(issues != null && issues.size()>0) {
			Collaborator.collaIssues.addAll(issues);
		}
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		if (existingIssue.getIssueName().equals(newIssue.getIssueName())
				&& existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
			return -1;
		} else {
			return 0;
		}
	}

	@Override
	public void extensionUnloaded() {// must imply IExtensionStateListener and call registerExtensionStateListener to make this function works
		Collaborator.stopCollaborating();
		Collaborator.collaIssues.clear();
		Collaborator.InteractionsList.clear();
		//清楚扫描的记录，想要重新扫描时，就可以通过重新加载插件来实现。（否则可能这些记录还在内存中？？）
	}


	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO Auto-generated method stub
		return null;
	}
}
