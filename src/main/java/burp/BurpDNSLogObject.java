package burp;

/**
 * 一个DNSlog对象，用于存储interactionID和server
 */
public class BurpDNSLogObject {
	private static IBurpCollaboratorClientContext DNSlogClient;//这个对象必须和BurpExtender中的对象是同一个
	String interactionID;//053bsqoev8gezev8oq59zylgv71xpm
	String subdomain;//053bsqoev8gezev8oq59zylgv71xpm
	String serverLocation;//burpcollaborator.net
	String fullPayload;// 053bsqoev8gezev8oq59zylgv71xpm.burpcollaborator.net

	public BurpDNSLogObject(){
		DNSlogClient = BurpExtender.DNSlogClient;//这个对象必须和BurpExtender中的对象是同一个
		this.subdomain = DNSlogClient.generatePayload(false);
		this.interactionID = subdomain;
		this.serverLocation = DNSlogClient.getCollaboratorServerLocation();
		this.fullPayload = subdomain+"."+serverLocation;
	}

	public String getInteractionID() {
		return interactionID;
	}

	public void setInteractionID(String interactionID) {
		this.interactionID = interactionID;
	}

	public String getSubdomain() {
		return subdomain;
	}

	public void setSubdomain(String subdomain) {
		this.subdomain = subdomain;
	}

	public String getServerLocation() {
		return serverLocation;
	}

	public void setServerLocation(String serverLocation) {
		this.serverLocation = serverLocation;
	}

	public String getFullPayload() {
		return fullPayload;
	}

	public void setFullPayload(String fullPayload) {
		this.fullPayload = fullPayload;
	}
}
