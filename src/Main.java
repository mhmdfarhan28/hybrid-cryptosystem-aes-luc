import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        //Parent root = FXMLLoader.load(getClass().getResource("fxml/UIEncrypt.fxml"));
        Parent root = FXMLLoader.load(getClass().getResource("fxml/UIDashboard.fxml"));
        primaryStage.setTitle("Hybrid Cryptosystem with AES and LUC");
        primaryStage.setScene(new Scene(root));
        javafx.scene.text.Font.getFamilies();
        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}
