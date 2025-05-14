interface ITestInterface {
  id: number;
  name: string;
}

const testConst: ITestInterface = {
  id: 1,
  name: "Test"
};

console.log(testConst);
