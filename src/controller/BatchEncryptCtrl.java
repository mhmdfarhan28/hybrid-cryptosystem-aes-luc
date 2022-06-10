package controller;


import aes.AES;
import aes.TestOutput;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.XYChart;
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
import javafx.stage.FileChooser;
import java.io.File;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ResourceBundle;


public class BatchEncryptCtrl implements Initializable {
    private Stage stage;
    private Scene scene;
    private Parent root;
    private final PseudoClass errorClass = PseudoClass.getPseudoClass("error");
    private final PseudoClass inactiveClass = PseudoClass.getPseudoClass("inactive");
    //TextField
    @FXML
    public TextField tf_inputtext;
    @FXML
    public TextField tf_sizerange;
    //Button
    @FXML
    private Button bt_table;
    @FXML
    private Button bt_chart1;
    @FXML
    private Button bt_chart2;
    @FXML
    private Button bt_copy;
    //Label
    @FXML
    public Text tx_sizeinput;
    //ComboBox
    @FXML
    public ComboBox<String> cb_seckeysize;
    @FXML
    public ComboBox<String> cb_multsize;
    //Table
    @FXML
    private TableView<TestOutput> table_output;
    @FXML
    private TableColumn<TestOutput,Long> col_textsize;
    @FXML
    private TableColumn<TestOutput,Long> col_aes_enctime;
    @FXML
    private TableColumn<TestOutput,Long> col_luc_enctime;
    @FXML
    private TableColumn<TestOutput,Long> col_aesluc_enctime;
    @FXML
    private TableColumn<TestOutput,Long> col_aes_dectime;
    @FXML
    private TableColumn<TestOutput,Long> col_luc_dectime;
    @FXML
    private TableColumn<TestOutput,Long> col_aesluc_dectime;

    ObservableList<TestOutput> outputlist = FXCollections.observableArrayList();
    //LineChart
    @FXML
    private LineChart<String,Number> lc_output1;
    @FXML
    private LineChart<String,Number> lc_output2;

    @Override
    public void initialize(URL url, ResourceBundle resourceBundle){
        cb_seckeysize.setItems(FXCollections.observableArrayList("128 bit","192 bit","256 bit"));
        cb_multsize.setItems(FXCollections.observableArrayList("2","4","8","16"));
        col_textsize.setCellValueFactory(new PropertyValueFactory<>("textsize"));
        col_aes_enctime.setCellValueFactory(new PropertyValueFactory<>("aes_enctime"));
        col_luc_enctime.setCellValueFactory(new PropertyValueFactory<>("luc_enctime"));
        col_aesluc_enctime.setCellValueFactory(new PropertyValueFactory<>("aesluc_enctime"));
        col_aes_dectime.setCellValueFactory(new PropertyValueFactory<>("aes_dectime"));
        col_luc_dectime.setCellValueFactory(new PropertyValueFactory<>("luc_dectime"));
        col_aesluc_dectime.setCellValueFactory(new PropertyValueFactory<>("aesluc_dectime"));
        table_output.setItems(outputlist);
        activeInactive(true,false,false);
    }

    //Button
    @FXML
    public void handleButtonFileChooser(MouseEvent event) throws IOException{
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open Resource File");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Text Files", "*.txt", "*.doc"));
        File file = fileChooser.showOpenDialog(((Node)event.getSource()).getScene().getWindow());
        tf_inputtext.setText(file.getPath());
        tx_sizeinput.setText(Files.readString(Path.of(tf_inputtext.getText())).length()+" byte");

    }
    @FXML
    public void handleButtonStart(MouseEvent event){
        Alert alert = new Alert(Alert.AlertType.ERROR);
        try{
            validateComboBox(cb_seckeysize, alert);
            validateComboBox(cb_multsize, alert);
            validateTextNumber(tf_sizerange, alert);
            validateText(tf_inputtext, alert);
            outputlist.removeAll(outputlist);
            int size = Integer.parseInt(cb_seckeysize.getValue().substring(0,3));

            AES aes = new AES(size);
            String inputtext = Files.readString(Path.of(tf_inputtext.getText()));
            String key = "8*t`.v<m[l0535EJ"; // 256 bit key
            key = key.substring(0,size/8);
            int[][] int_key = aes.getMatriksKey(key.getBytes("UTF-16BE"));
            byte[] byte_key = aes.reserveMatriks(int_key);
            LUC luc = new LUC(8);
            //luc.setPublicKey();

            int multsize = Integer.parseInt(cb_multsize.getValue());
            int range = Integer.parseInt(tf_sizerange.getText());
            for (int i =1; i<=range;i*=multsize){
                //Encrypt
                String text = inputtext.substring(0,i);
                long startTimeAES_enc = System.nanoTime();
                String enctext = aes.ecb_encrypt(text,int_key);
                long endTimeAES_enc   = System.nanoTime();

                long startTimeLUC_enc = System.nanoTime();
                BigInteger[] cipherkey = luc.enc(byte_key, BigInteger.valueOf(233), BigInteger.valueOf(42781));
                long endTimeLUC_enc   = System.nanoTime();
                String enckey = luc.bigIntToString(cipherkey);

                long timeAES_enc = endTimeAES_enc - startTimeAES_enc;
                long timeLUC_enc = endTimeLUC_enc - startTimeLUC_enc;
                long timeAESLUC_enc = timeLUC_enc + timeAES_enc;

                //Decrypt
                BigInteger[] bigIntegers_enckey = luc.stringToBigInt(enckey);
                long startTimeLUC_dec = System.nanoTime();
                String deckey = luc.dec(bigIntegers_enckey, BigInteger.valueOf(233), BigInteger.valueOf(42781), BigInteger.valueOf(179), BigInteger.valueOf(239));
                long endTimeLUC_dec = System.nanoTime();

                int_key = aes.getMatriksKey(deckey.getBytes("UTF-16BE"));
                long startTimeAES_dec = System.nanoTime();
                aes.ecb_decrypt(enctext,int_key);
                long endTimeAES_dec   = System.nanoTime();

                long timeAES_dec = endTimeAES_dec - startTimeAES_dec;
                long timeLUC_dec = endTimeLUC_dec - startTimeLUC_dec;
                long timeAESLUC_dec = timeLUC_dec + timeAES_dec;


                int[][][] intText = aes.stringToHex(enctext);
                int blok = intText.length;
                outputlist.add(new TestOutput((long)text.length(), timeAES_enc, timeLUC_enc, timeAESLUC_enc,
                        timeAES_dec, timeLUC_dec, timeAESLUC_dec));
                //outputlist.add(new TestOutput((long)text.length(), (float)timeAES_enc/1000000, (long)timeLUC_enc/1000000, (long)timeAESLUC_enc/1000000,
                 //       (float)timeAES_dec/1000000, (float)timeLUC_dec/1000000, (long)timeAESLUC_dec/1000000));
            }
        }
        catch (Exception e){
            alert.setTitle("Error");
            alert.setHeaderText("Your input was invalid");
            alert.showAndWait();
        }
    }
    @FXML
    public void handleButtonTable(MouseEvent event) {
        activeInactive(true,false,false);
    }
    @FXML
    public void handleButtonChart1(MouseEvent event) {
        activeInactive(false,true,false);
        lc_output1.getData().clear();
        XYChart.Series<String, Number> series = new  XYChart.Series<String, Number>();
        series.setName("AES Encryption Time");
        for (int i=0;i<outputlist.size();i++){
            series.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getAes_enctime()));
        }
        lc_output1.getData().add(series);
        XYChart.Series<String, Number> series2 = new  XYChart.Series<String, Number>();
        for (int i=0;i<outputlist.size();i++){
            series2.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getLuc_enctime()));
        }
        series2.setName("LUC Encryption Time");
        lc_output1.getData().add(series2);
        XYChart.Series<String, Number> series3 = new  XYChart.Series<String, Number>();
        for (int i=0;i<outputlist.size();i++){
            series3.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getAesluc_enctime()));
        }
        series3.setName("AES+LUC Encryption Time");
        lc_output1.getData().add(series3);

    }
    @FXML
    public void handleButtonChart2(MouseEvent event) {
        activeInactive(false,false,true);
        lc_output2.getData().clear();
        XYChart.Series<String, Number> series = new  XYChart.Series<String, Number>();
        series.setName("AES Decryption Time");
        for (int i=0;i<outputlist.size();i++){
            series.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getAes_dectime()));
        }
        lc_output2.getData().add(series);
        XYChart.Series<String, Number> series2 = new  XYChart.Series<String, Number>();
        for (int i=0;i<outputlist.size();i++){
            series2.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getLuc_dectime()));
        }
        series2.setName("AES+LUC Decryption Time");
        lc_output2.getData().add(series2);
        XYChart.Series<String, Number> series3 = new  XYChart.Series<String, Number>();
        for (int i=0;i<outputlist.size();i++){
            series3.getData().add(new XYChart.Data<String, Number>(outputlist.get(i).getTextsize()+"",outputlist.get(i).getAesluc_dectime()));
        }
        series3.setName("AES+LUC Decryption Time");
        lc_output2.getData().add(series3);

    }
    @FXML
    public void handleButtonCopy(MouseEvent event) {
        final Clipboard clipboard = Clipboard.getSystemClipboard();
        final ClipboardContent content = new ClipboardContent();
        String text ="";
        for (int i=0;i<outputlist.size();i++){
            text += outputlist.get(i).getTextsize()+"\t"+outputlist.get(i).getAes_enctime()+"\t"+outputlist.get(i).getLuc_enctime()+"\t"+outputlist.get(i).getAesluc_enctime()
                    +"\t"+outputlist.get(i).getAes_dectime()+"\t"+outputlist.get(i).getLuc_dectime()+"\t"+outputlist.get(i).getAesluc_dectime()+"\n";
        }
        content.putString(text);
        clipboard.setContent(content);
        bt_copy.setText("Copied");
    }

    public void activeInactive(boolean table, boolean chart1, boolean chart2){
        bt_table.pseudoClassStateChanged(inactiveClass, !table);
        bt_chart1.pseudoClassStateChanged(inactiveClass, !chart1);
        bt_chart2.pseudoClassStateChanged(inactiveClass, !chart2);
        table_output.setVisible(table);
        lc_output1.setVisible(chart1);
        lc_output2.setVisible(chart2);
    }


    private void validateComboBox(ComboBox cb, Alert alert) {
        if (cb.getValue() == null) {
            cb.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Please fill out the form!");
        } else {
            cb.pseudoClassStateChanged(errorClass, false);
        }
    }

    private void validateText(TextField tf, Alert alert) {
        try{
            Files.readString(Path.of(tf_inputtext.getText()));
            tf.pseudoClassStateChanged(errorClass, false);
        }
        catch (Exception e){
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("File path doesn't exist or invalid");
            if (tf.getText().trim().length()==0) {
                alert.setContentText("Please fill out the form!");
            }

        }
    }

    private void validateTextNumber(TextField tf, Alert alert) {
        try {
            int size = Integer.parseInt(tf.getText());
            if (size > Files.readString(Path.of(tf_inputtext.getText())).length()) {
                tf.pseudoClassStateChanged(errorClass, true);
                alert.setContentText("Range must be less or equal than the input text size");
            }
            else{
                tf.pseudoClassStateChanged(errorClass, false);
            }
        }
        catch(Exception e){
            tf.pseudoClassStateChanged(errorClass, true);
            alert.setContentText("Range must be a number!");
            if (tf.getText().trim().length()==0) {
                alert.setContentText("Please fill out the form!");
            }
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
