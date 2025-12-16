import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Scanner;

public class Chall {
    private final static int Q = 5;

    public static void main(String[] args) {
        try {
            final String FLAG = Files.readString(Paths.get("flag.txt"), StandardCharsets.UTF_8);

            try (final Scanner scan = new Scanner(System.in)) {
                for (int i = 0; i < Q; i++) {
                    final Random random = new Random();

                    final int leak = random.nextInt();
                    System.out.println("leak: " + leak);

                    System.out.printf("guess: ");
                    System.out.flush();
                    final int guess = scan.nextInt();
                    
                    if (guess != random.nextInt()) {
                        System.out.println("wrong");
                        System.exit(1);
                    }
                }
                System.out.println(FLAG);
            }
        } catch (IOException e) {
            System.exit(1);
        }
    }
}
