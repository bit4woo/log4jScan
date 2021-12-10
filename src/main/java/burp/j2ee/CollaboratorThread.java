package burp.j2ee;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import burp.BurpExtender;
import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IScanIssue;

public class CollaboratorThread extends Thread {
	//Interval constants
	private static final long THREAD_SLEEP_INTERVAL = 1000;
	private static final long COLLAB_POLL_INTERVAL = 1*60*1000;//1分钟
	private static final long ISSUE_SHOULD_REMOVE = 8*60*1000;//五分钟

	//Collaborator context object used to poll the server
	private final IBurpCollaboratorClientContext _collabContext;

	public List<IScanIssue> collaIssues = new ArrayList<IScanIssue>();
	public List<IBurpCollaboratorInteraction> InteractionsList = new ArrayList<IBurpCollaboratorInteraction>();


	//Thread data
	private boolean _stopFlag;
	private long _lastPollTime;
	IBurpExtenderCallbacks callbacks;

	/*******************
	 *
	 * 
	 * @param collabContext The Collaborator context object from Burp Suite.
	 * @param modules A list of all loaded scanner modules that use Collaborator.
	 ******************/
	public CollaboratorThread(IBurpExtenderCallbacks callbacks,IBurpCollaboratorClientContext collabContext) {
		// pass callbacks to debug
		_collabContext = collabContext;
		_stopFlag = false;
		_lastPollTime = 0;
		this.callbacks = callbacks;
	}

	/*******************
	 * Set the flag indicating that the Collaborator thread should terminate.
	 ******************/
	public void stopCollaborating() {
		_stopFlag = true;
	}

	/*******************
	 * Periodically poll the Collaborator server for interactions and dispatch
	 * them to scanner modules to handle and report issues.
	 ******************/
	public void run() {

		while(_stopFlag == false) {
			if(System.currentTimeMillis() - _lastPollTime >= COLLAB_POLL_INTERVAL) {
				try {
					_lastPollTime = System.currentTimeMillis();	

					freshInteractionsFromServer();
					freshIssues();

					callbacks.printOutput("\n"+new Date(System.currentTimeMillis())+" : "+InteractionsList.size()+" interactions and "+collaIssues.size()+" issues found");

					if (collaIssues.size()>0 && InteractionsList.size()>0) {

						for(int j = 0; j < collaIssues.size(); ++j) {
							for(int i = 0; i < InteractionsList.size(); ++i) {
								CustomScanIssue issue = (CustomScanIssue)collaIssues.get(j);
								String IDofColl =InteractionsList.get(i).getProperty("interaction_id");
								String IDofIssue =issue.getInteractionID();
								//_callbacks.printOutput(IDofIssue);
								//_callbacks.printOutput(IDofColl+":::"+IDofIssue);
								if(IDofColl.equalsIgnoreCase(IDofIssue)) {
									//这里报告的漏洞只会出现在target中，不会出现在scan queue！！！
									String newDetailString = issue.getIssueDetail()+ getInteractionDetail(InteractionsList.get(i));
									issue.setIssueDetail(newDetailString);
									callbacks.addScanIssue(issue);
									callbacks.printOutput(issue.getIssueName()+" scan issue added!!!");
									collaIssues.remove(j);
								}
							}
						}
					}
				}catch(Exception e) {
					callbacks.printError(e.getMessage());
				}
			}

			try { 
				Thread.sleep(THREAD_SLEEP_INTERVAL); 
			} catch(Exception e) {
				callbacks.printError(e.getMessage());
			}
		}
	}

	/*
	 * 从服务器获取所有DNS或HTTP交互记录，并加入本地存储
	 */
	public void freshInteractionsFromServer() {
		List<IBurpCollaboratorInteraction> interactions = _collabContext.fetchAllCollaboratorInteractions();

		//cache Interaction IDs here.
		for(int i = 0; i < interactions.size(); ++i) {
			/*
			//debug print
			Map<java.lang.String,java.lang.String> currentProperties = interactions.get(i).getProperties();
			Set<String> a = currentProperties.keySet();
			Iterator<String> b = a.iterator();
			while(b.hasNext()) {
				String d = b.next();
				_callbacks.printOutput(d);
				_callbacks.printOutput(currentProperties.get(d));
			}
			 */

			if (InteractionsList.size()>=100) {
				InteractionsList.remove(0);//delete first one
			}

			//InteractionsList.add(interactions.get(i).getProperty("interaction_id"));//只是保存id,也就是那个子域名
			InteractionsList.add(interactions.get(i));
			//add to end
		}
	}


	/*
	 * 维护本地Issue保存记录：删除过时的，删除超容量的
	 */
	public void freshIssues() {
		for(int j = 0; j < collaIssues.size(); ++j) {
			CustomScanIssue issue = (CustomScanIssue)collaIssues.get(j);
			if(collaIssues.get(j)==null) {
				collaIssues.remove(j);
			}else if(System.currentTimeMillis() - issue.getSendTime()> ISSUE_SHOULD_REMOVE) {
				collaIssues.remove(j);// remove issues that more than 8 minutes;
				//_callbacks.printOutput("remove "+issues.get(j).getInteractionID());
			}
		}

		while(collaIssues.size()>=300) {
			collaIssues.remove(0);
		}
	}

	public String getInteractionDetail(IBurpCollaboratorInteraction interaction) {
		// 公共属性 interaction_id, type, client_ip, and time_stamp.
		// DNS查询的属性： query_type and raw_query(Base64)
		// HTTP请求的属性：protocol, request(Base64), and response(Base64).

		StringBuilder detail = new StringBuilder();
		String interaction_id = interaction.getProperty("interaction_id");
		String bchost = interaction_id + ".burpcollaborator.net";
		String type = interaction.getProperty("type");
		String client_ip = interaction.getProperty("client_ip");
		String time_stamp = interaction.getProperty("time_stamp");

		detail.append("<br><br><strong>BurpCollaborator data:</strong><br><br>");
		detail.append("<br><strong>Interaction id: </strong>" + interaction_id);
		detail.append("<br><strong>type: </strong>" + type);
		detail.append("<br><strong>client_ip: </strong>" + client_ip );
		detail.append("<br><strong>time_stamp: </strong>" + time_stamp);

		if (type.equalsIgnoreCase("DNS")) {
			String query_type = interaction.getProperty("query_type");
			String raw_query = interaction.getProperty("raw_query");

			detail.append("<br><strong>query_type: </strong>" + query_type);
			detail.append("<br><strong>raw_query: </strong>" + raw_query);
			detail.append("<br><strong>raw_query_decoded: </strong>" + new String(BurpExtender.getCallbacks().getHelpers().base64Decode(raw_query)));
		}else {
			String protocol = interaction.getProperty("protocol");
			String request = interaction.getProperty("request");
			String response = interaction.getProperty("response");

			detail.append("<br><strong>protocol: </strong>" + protocol );
			detail.append("<br><strong>request: </strong>" + request );
			detail.append("<br><strong>response: </strong>" + response);
		}
		return detail.toString();
	}
}
