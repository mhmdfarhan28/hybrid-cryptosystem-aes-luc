package controller;


import aes.AES;
import javafx.scene.control.Button;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import luc.LUC;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ComboBox;
import javafx.scene.input.KeyEvent;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.text.Text;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ResourceBundle;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.scene.Node;


public class GenKeyCtrl implements Initializable {
    private Stage stage;
    private Scene scene;
    private Parent root;
    //TextField
    public TextField tf_inputpubkey;
    @FXML
    public TextField tf_inputNkey;
    @FXML
    public TextField tf_inputPkey;
    @FXML
    public TextField tf_inputQkey;
    //Button
    @FXML
    public Button bt_copy;
    //ComboBox
    @FXML
    public ComboBox<String> cb_maxkeysize;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle){
        cb_maxkeysize.setItems(FXCollections.observableArrayList("8 bit","10 bit","12 bit"));
        cb_maxkeysize.setValue("8 bit");
    }

    //Button
    @FXML
    public void handleButtonGenerate(MouseEvent event) {
        int size = Integer.parseInt(cb_maxkeysize.getValue().replace(" bit", ""));
        LUC luc = new LUC(size);
        luc.setPublicKey();
        tf_inputpubkey.setText(luc.getE()+"");
        tf_inputNkey.setText(luc.getN()+"");
        tf_inputPkey.setText(luc.getP()+"");
        tf_inputQkey.setText(luc.getQ()+"");

    }
    @FXML
    public void handleButtonCopy1(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        content.putString(tf_inputpubkey.getText()+
                " "+tf_inputPkey.getText()+
                " "+tf_inputQkey.getText()+
                " "+tf_inputNkey.getText());
        clipboard.setContent(content);
        bt_copy.setText("Copied");

    }

    @FXML
    public void handleButtonDashboard(MouseEvent event) throws Exception {
        root = FXMLLoader.load(getClass().getResource("../fxml/UIDashboard.fxml"));
        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    @FXML
    public void handleButtonAvalanche(MouseEvent event) throws Exception {
        root = FXMLLoader.load(getClass().getResource("../fxml/UIAvalancheTest.fxml"));
        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    @FXML
    public void handleButtonBatchTest(MouseEvent event) throws Exception {
        root = FXMLLoader.load(getClass().getResource("../fxml/UIBatchEncryptTest.fxml"));
        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
}
