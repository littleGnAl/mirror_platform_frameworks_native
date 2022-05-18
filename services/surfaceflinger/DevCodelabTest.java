package ;

import static com.google.common.truth.Truth.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class DevCodelabTest {

  @Before
  public void setUp() {

  }

  // Do not submit attn: Rename this method, add others, and make actual assertions.
  @Test
  public void behaviorBeingTested_expectedResult() {
    assertThat("I have written a test").contains("false");
  }
}
