
package lanchatapplication;

import javax.swing.SwingWorker;
import privateChat.PrivateChat;


public class HandlePrivateChat extends SwingWorker<Void, Void> {

    @Override
    protected Void doInBackground() throws Exception {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        new PrivateChat().showOptionsCreateServerJoinServer();
        return null;
    }
    
}