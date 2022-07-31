import { Config, parseConfigFile } from "@verdaccio/config";
import { FixedToken } from "../src/fixed-token";
import { IConfig } from "../src/config";
import path from "path";

describe("fixed-token", () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  describe("ahthenticate()", () => {
    test("success", () => {
      const testConfig = new Config(
        parseConfigFile(path.join(__dirname, "./__fixtures__/config.yaml"))
      ) as any as IConfig;
      const t = new FixedToken(testConfig);
      const tosuccess = (username: string) => (error, allow: string[]) => {
        try {
          expect(error).toBeNull();
          expect(allow).toContain(username);
        } catch (error) {
          console.log(`failed ${username}`);
          throw error;
        }
      };
      const tofail = (_username: string) => (error, allow: string[]) => {
        expect(error).toBeNull();
        expect(allow).toBeNull();
      };
      const successUsers = [
        { name: "trueuser", password: "testuser" },
        { name: "trueuser2", password: "testuser2" },
      ];

      for (const u of successUsers) {
        t.authenticate(u.name, u.password, tosuccess(u.name));
      }
      t.authenticate("faileuser", "truepassword", tofail("faileuser"));
    });
  });
});
