package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IScannerListener,
        IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("BurpTemplate");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        callbacks.registerHttpListener(this);
        callbacks.registerProxyListener(this);
        callbacks.registerScannerListener(this);
        callbacks.registerExtensionStateListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        //Request 조작
        if (messageIsRequest) {
            // Origin Request Parsing
            IRequestInfo requestInfo = this.helpers.analyzeRequest(messageInfo.getRequest());
            //URL url = requestInfo.getUrl(); <- java.net.URL로 Request 처리 가능

            stdout.println("-- Origin Request : ");
            // Header 정보
            List<String> strOriginHeaderList = requestInfo.getHeaders();
            for (String header : strOriginHeaderList) {
                stdout.println(header);
            }
            stdout.println();
            // Body 정보 확인
            int bodyOffset = this.helpers.analyzeRequest(messageInfo.getRequest()).getBodyOffset();
            byte[] byteOriginBody = Arrays.copyOfRange(messageInfo.getRequest(), bodyOffset,
                    (messageInfo.getRequest()).length);
            String strOriginBody = new String(byteOriginBody);
            stdout.println(strOriginBody);


            // Request 의 Header 및 Body 값 조작
            stdout.println("-- Modified Request : ");
            List<String> strModifiedHeaderList = new ArrayList<>();
            for (String header : strOriginHeaderList) {
                strModifiedHeaderList.add(header);
                stdout.println(header);
            }
            stdout.println();
            String strModifiedBody = strOriginBody;
            stdout.println(strModifiedBody);


            // 조작된 Request를 httpMessage로 만들어서 전송
            byte[] httpMessage = this.helpers.buildHttpMessage(strModifiedHeaderList,
                    strModifiedBody.getBytes());
            messageInfo.setRequest(httpMessage);


        } else {
//
//            IResponseInfo responseInfo = this.helpers.analyzeResponse(messageInfo.getResponse());
//            List<String> strOriginHeaderList = responseInfo.getHeaders();
//
//            stdout.println("-- Origin Response : ");
//            for (String header : strOriginHeaderList) {
//                stdout.println(header);
//            }
//            stdout.println();
//
//            int bodyOffset = this.helpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset();
//            byte[] byteOriginBody = Arrays.copyOfRange(messageInfo.getResponse(),
//                    bodyOffset, (messageInfo.getResponse()).length);
//            String strOriginBody = new String(byteOriginBody);
//            stdout.println(strOriginBody);
//
//
//            // Request 의 Header 및 Body 값 조작
//            stdout.println("-- Modified Response : ");
//            List<String> strModifiedHeaderList = new ArrayList<>();
//            for (String header : strOriginHeaderList) {
//                strModifiedHeaderList.add(header);
//                stdout.println(header);
//            }
//            stdout.println();
//            String strModifiedBody = strOriginBody;
//            stdout.println(strModifiedBody);
//
//
//            byte[] httpMessage = this.helpers.buildHttpMessage(strModifiedHeaderList, strModifiedBody.
//                    getBytes());
//            messageInfo.setResponse(httpMessage);
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo requestInfo = this.helpers.analyzeRequest(messageInfo.getRequest());
            //URL url = requestInfo.getUrl(); <- java.net.URL로 Request 처리 가능

            stdout.println("-- Origin Proxy Request : ");
            // Header 정보
            List<String> strOriginHeaderList = requestInfo.getHeaders();
            for (String header : strOriginHeaderList) {
                stdout.println(header);
            }
            stdout.println();
            // Body 정보 확인
            int bodyOffset = this.helpers.analyzeRequest(messageInfo.getRequest()).getBodyOffset();
            byte[] byteOriginBody = Arrays.copyOfRange(messageInfo.getRequest(), bodyOffset,
                    (messageInfo.getRequest()).length);
            String strOriginBody = new String(byteOriginBody);
            stdout.println(strOriginBody);


            // Request 의 Header 및 Body 값 조작
            stdout.println("-- Modified Proxy Request : ");
            List<String> strModifiedHeaderList = new ArrayList<>();
            for (String header : strOriginHeaderList) {
                strModifiedHeaderList.add(header);
                stdout.println(header);
            }
            stdout.println();
            String strModifiedBody = strOriginBody;
            stdout.println(strModifiedBody);


            // Request 생성
            byte[] httpMessage = this.helpers.buildHttpMessage(strModifiedHeaderList,
                    strModifiedBody.getBytes());
            messageInfo.setRequest(httpMessage);

        }
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Extension was unloaded");
    }

    @Override
    public void newScanIssue(IScanIssue issue) {
        stdout.println("New scan issue : " + issue.getIssueName());
    }
}
