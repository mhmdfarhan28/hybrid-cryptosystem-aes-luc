package controller;


import aes.AES;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.Stage;
import luc.LUC;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.MouseEvent;
import javafx.scene.text.Text;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.ResourceBundle;


public class EncryptCtrl implements Initializable {
    private Stage stage;
    private Scene scene;
    private Parent root;
    private final PseudoClass errorClass = PseudoClass.getPseudoClass("error");
    //TextField
    @FXML
    public TextField tf_inputtext;
    @FXML
    public TextField tf_inputseckey;
    @FXML
    public TextField tf_inputpubkey;
    @FXML
    public TextField tf_inputNkey;
    @FXML
    public TextField tf_outputtext;
    @FXML
    public TextField tf_outputseckey;
    //Button
    @FXML
    public Button bt_copy1;
    @FXML
    public Button bt_copy2;
    //Label
    @FXML
    public Text tx_sizeinput;
    @FXML
    public Text tx_sizeoutput;
    @FXML
    public Text tx_encryptime;
    @FXML
    public Text tx_seckeytime;
    @FXML
    public Text tx_totaltime;
    //ComboBox
    @FXML
    public ComboBox<String> cb_seckeysize;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle){
        cb_seckeysize.setItems(FXCollections.observableArrayList("128 bit","192 bit","256 bit"));
    }

    @FXML
    public void handleInputText(KeyEvent event){
        tx_sizeinput.setText(tf_inputtext.getLength()*2+" byte");
    }
    @FXML
    public void handleOutputText(KeyEvent event){
        String[] temp = tx_sizeinput.getText().split(" ");
        tx_sizeoutput.setText("size : "+temp.length+" byte");
    }

    //Button
    @FXML
    public void handleButtonEncrypt(MouseEvent event) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        try {
            validateSecretKeySize(cb_seckeysize, alert);
            validateText(tf_inputtext, alert);
            validateSecretKey(tf_inputseckey, alert);
            validateTextNumber(tf_inputpubkey, alert);
            validateTextNumber(tf_inputNkey, alert);

            int size = Integer.parseInt(cb_seckeysize.getValue().substring(0, 3));
            String text = tf_inputtext.getText();
            String key = tf_inputseckey.getText();

            long startTimeAES = System.nanoTime();
            AES aes = new AES(size);
            int[][] intkey = aes.getMatriksKey(key.getBytes("UTF-16BE"));
            String enctext = aes.ecb_encrypt(text, intkey);
            tf_outputtext.setText(enctext);
            long endTimeAES = System.nanoTime();
            int[][][] intText = aes.stringToHex(enctext);
            int blok = intText.length*2;
            tx_sizeoutput.setText(blok*16 + " byte");
            tx_encryptime.setText((endTimeAES - startTimeAES) + " nanosecond");

            long startTimeLUC = System.nanoTime();
            LUC luc = new LUC();
            BigInteger[] cipherkey = luc.enc(aes.reserveMatriks(intkey), new BigInteger(tf_inputpubkey.getText()), new BigInteger(tf_inputNkey.getText()));
            System.out.println("Cipher key = " + luc.bigIntToString(cipherkey));
            tf_outputseckey.setText(luc.bigIntToString(cipherkey));
            long endTimeLUC = System.nanoTime();
            tx_seckeytime.setText((endTimeLUC - startTimeLUC) + " nanosecond");
            tx_totaltime.setText((endTimeLUC - startTimeAES) + " nanosecond");
        }
        catch(Exception e){
            alert.setTitle("Error");
            alert.setHeaderText("Your input was invalid");
            alert.showAndWait();
        }
    }

    private void validateSecretKeySize(ComboBox cb, Alert alert) {
        if (cb.getValue() == null) {
            cb.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Please fill out the form!");
        } else {
            cb.pseudoClassStateChanged(errorClass, false);
        }
    }

    private void validateSecretKey(TextField tf, Alert alert) {
        try{
            int size = Integer.parseInt(cb_seckeysize.getValue().substring(0, 3))/16;
            if (tf.getText().trim().length() !=  size) {
                tf.pseudoClassStateChanged(errorClass, true);
                alert.setContentText("The Secret Key was supposed to be only "+ size +" characters, need "+(size-tf.getLength()));
            }
            else {
                tf.pseudoClassStateChanged(errorClass, false);
            }
        }
        catch(Exception e){
            tf.pseudoClassStateChanged(errorClass, true);
        }
    }

    private void validateText(TextField tf, Alert alert) {
        if (tf.getText().trim().length()==0) {
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Please fill out the form!");
        } else {
            tf.pseudoClassStateChanged(errorClass, false);
        }
    }

    private void validateTextNumber(TextField tf, Alert alert) {
        try {
            Integer.parseInt(tf.getText());
            tf.pseudoClassStateChanged(errorClass, false);
        }
        catch(Exception e){
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Public Key and N Key must be a number!");
            if (tf.getText().trim().length()==0) {
                alert.setContentText("Please fill out the form!");
            }
        }
    }

    @FXML
    public void handleButtonCopy1(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        content.putString(tf_outputtext.getText());
        clipboard.setContent(content);
        bt_copy1.setText("Copied");
    }
    @FXML
    public void handleButtonCopy2(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        content.putString(tf_outputseckey.getText());
        clipboard.setContent(content);
        bt_copy2.setText("Copied");
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
