import path from "path";
import { Application, NextFunction, Request, Response } from "express";
import { RemoteUser } from "@verdaccio/types";
import { Config, parseConfigFile } from "@verdaccio/config";
import { FixedToken, IAuth } from "../src/fixed-token";
import { IConfig } from "../src/config";

describe("fixed-token", () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  const nextFunction: NextFunction = jest.fn();
  const testConfig = new Config(
    parseConfigFile(path.join(__dirname, "./__fixtures__/config.yaml"))
  ) as unknown as IConfig;

  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    mockRequest = {};
    mockResponse = {};
  });

  describe("express func()", () => {
    test("without header", async () => {
      const t = new FixedToken(testConfig);

      await t.hookToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toBeCalled();
    });

    test("without authrization header", async () => {
      const t = new FixedToken(testConfig);
      mockRequest = {
        headers: {},
      };
      await t.hookToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toBeCalled();
    });

    test("with invalid authrization header", async () => {
      const t = new FixedToken(testConfig);
      mockRequest = {
        headers: {
          authorization: "Bearer ok",
        },
      };
      await t.hookToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toBeCalled();
    });

    test("with true authrization header", async () => {
      const t = new FixedToken(testConfig);
      const mockAuth: IAuth = {
        config: testConfig,
        jwtEncrypt: async (user: RemoteUser): Promise<string> => {
          return user.name + "_dummyresponse";
        },
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        apiJWTmiddleware: () => () => {},
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        webUIJWTmiddleware: () => () => {},
        aesEncrypt: () => {
          return Buffer.from("");
        },
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        authenticate: () => {},
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        changePassword: () => {},
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        allow_access: () => {},
        // eslint-disable-next-line @typescript-eslint/no-empty-function
        add_user: () => {},
      };
      t.register_middlewares(
        {
          // eslint-disable-next-line @typescript-eslint/no-empty-function
          use: () => {},
        } as Application,
        mockAuth
      );

      mockRequest = {
        headers: {
          authorization: "Bearer token_for_trueuser",
        },
      };
      await t.hookToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toBeCalled();
      expect(mockRequest.headers).toEqual(
        expect.objectContaining({
          authorization: "Bearer trueuser_dummyresponse",
        })
      );

      mockRequest = {
        headers: {
          authorization: "Bearer unknown_token",
        },
      };
      await t.hookToken(
        mockRequest as Request,
        mockResponse as Response,
        nextFunction
      );
      expect(nextFunction).toBeCalled();
      expect(mockRequest.headers).toEqual(
        expect.objectContaining({
          authorization: "Bearer unknown_token",
        })
      );
    });
  });

  describe("ahthenticate()", () => {
    test("success", () => {
      const t = new FixedToken(testConfig);
      const tosuccess = (username: string) => (error: any, allow: string[]) => {
        try {
          expect(error).toBeNull();
          expect(allow).toContain(username);
        } catch (error) {
          console.log(`failed ${username}`);
          throw error;
        }
      };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const tofail = (_username: string) => (error: any, allow: string[]) => {
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
