package lanchatapplication;

import groupChat.GroupChat;
import javax.swing.SwingWorker;


public class HandleGroupChat extends SwingWorker<Void, Void> {

    @Override
    protected Void doInBackground() throws Exception {
        //throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
        new GroupChat().showOptionsCreateServerJoinServer();
        return null;
    }
    
}