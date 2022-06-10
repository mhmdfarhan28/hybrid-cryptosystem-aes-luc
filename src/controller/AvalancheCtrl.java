package controller;


import aes.AES;
import aes.TestOutput;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
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
import java.util.ResourceBundle;


public class AvalancheCtrl implements Initializable {
    private Stage stage;
    private Scene scene;
    private Parent root;
    private final PseudoClass errorClass = PseudoClass.getPseudoClass("error");
    //TextField
    @FXML
    public TextField tf_inputtext1;
    @FXML
    public TextField tf_inputtext2;
    @FXML
    public TextField tf_inputtext3;
    @FXML
    public TextField tf_inputtext4;
    @FXML
    public TextField tf_inputseckey;
    @FXML
    public TextField tf_inputpubkey;
    @FXML
    public TextField tf_inputNkey;

    @FXML
    public TextField tf_aes_c1;
    @FXML
    public TextField tf_aes_c2;
    @FXML
    public TextField tf_aes_bitdif;
    @FXML
    public TextField tf_aes_ae;

    @FXML
    public TextField tf_luc_c1;
    @FXML
    public TextField tf_luc_c2;
    @FXML
    public TextField tf_luc_bitdif;
    @FXML
    public TextField tf_luc_ae;
    //Button
    @FXML
    public Button bt_copy1;
    @FXML
    public Button bt_copy2;
    //Label
    @FXML
    public Text tx_sizeinput;
    //ComboBox
    @FXML
    public ComboBox<String> cb_seckeysize;
    @FXML
    public ComboBox<String> cb_round;

    private int[] aes_bitdif;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle){
        cb_seckeysize.setItems(FXCollections.observableArrayList("128 bit","192 bit","256 bit"));
        cb_round.setItems(FXCollections.observableArrayList("Round 0","Round 1","Round 2","Round 3","Round 4","Round 5","Round 6","Round 7"
                ,"Round 8","Round 9","Round 10","Round 11","Round 12","Round 13","Round 14"));
    }

    @FXML
    public void handleInputText(KeyEvent event){
        tx_sizeinput.setText("size : "+tf_inputtext1.getLength()*2+" byte");
    }

    //Button
    @FXML
    public void handleButtonEncrypt(MouseEvent event) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        try{
            validateSecretKeySize(cb_seckeysize, alert);
            validateText(tf_inputtext1, alert);
            validateText(tf_inputtext2, alert);
            validateSecretKey(tf_inputseckey, alert);
            validateText(tf_inputtext3, alert);
            validateText(tf_inputtext4, alert);
            validateTextNumber(tf_inputpubkey, alert);
            validateTextNumber(tf_inputNkey, alert);
            int size = Integer.parseInt(cb_seckeysize.getValue().substring(0,3));

            AES aes1 = new AES(size);
            AES aes2 = new AES(size);
            String text1 = tf_inputtext1.getText();
            String text2 = tf_inputtext2.getText();
            String key = tf_inputseckey.getText();
            int[][] intkey = aes1.getMatriksKey(key.getBytes("UTF-16BE"));
            tf_aes_c1.setText(aes1.ecb_encrypt(text1,intkey));
            int[][] state1 = aes1.getStateRound();
            tf_aes_c2.setText(aes2.ecb_encrypt(text2,intkey));
            int[][] state2 = aes2.getStateRound();
            aes_bitdif = new int[aes1.getNr()+1];
            for (int i=0;i<aes_bitdif.length;i++){
                aes_bitdif[i] =  aes1.getBitDif(state1[i], state2[i]);
            }
            tf_aes_bitdif.setText(aes_bitdif[0]+"");
            tf_aes_ae.setText(aes1.avalanche(tf_aes_c1.getText(),tf_aes_c2.getText()));

            LUC luc = new LUC();
            byte[]  text3 = tf_inputtext3.getText().getBytes("UTF-16BE");
            System.out.println(text3.length);
            byte[]  text4 = tf_inputtext4.getText().getBytes("UTF-16BE");
            String x = luc.bigIntToString(luc.enc(text3, new BigInteger(tf_inputpubkey.getText()), new BigInteger(tf_inputNkey.getText())));
            String y = luc.bigIntToString(luc.enc(text4, new BigInteger(tf_inputpubkey.getText()), new BigInteger(tf_inputNkey.getText())));
            tf_luc_c1.setText(x);
            tf_luc_c2.setText(y);
            tf_luc_ae.setText(luc.avalanche(tf_luc_c1.getText(),tf_luc_c2.getText()));
            tf_luc_bitdif.setText(luc.getBitDif()+"");
        }
        catch (Exception e){
            alert.setTitle("Error");
            alert.setHeaderText("Your input was invalid");
            alert.showAndWait();
        }


    }

    @FXML
    public void handleRound(ActionEvent event){
        try {
            int round = Integer.parseInt(cb_round.getValue().substring(6));
            tf_aes_bitdif.setText(aes_bitdif[round] + "");
        }
        catch (Exception e){
            tf_aes_bitdif.setText("");
        }

    }

    @FXML
    public void handleButtonCopy1(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        String text ="";
        for (int i=0;i<aes_bitdif.length;i++){
            text += aes_bitdif[i]+"\t";
        }
        content.putString(text);
        clipboard.setContent(content);
        bt_copy1.setText("Copied");
    }
    @FXML
    public void handleButtonCopy2(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        content.putString(tf_luc_c1.getText()+"\t"+tf_luc_c2.getText()+"\t\n"+tf_luc_bitdif.getText()+"\t\n"+tf_luc_ae.getText());
        clipboard.setContent(content);
        bt_copy2.setText("Copied");
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
            int size = Integer.parseInt(cb_seckeysize.getValue().substring(0, 3))/8;
            if (tf.getText().trim().length() !=  size) {
                tf.pseudoClassStateChanged(errorClass, true);
                alert.setContentText("The Secret Key was supposed to be only "+ size +" characters");
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
        }
        catch(Exception e){
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Public Key and N Key must be a number!");
        }
        if (tf.getText().trim().length()==0) {
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Please fill out the form!");
        }
        else {
            tf.pseudoClassStateChanged(errorClass, false);
        }
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
