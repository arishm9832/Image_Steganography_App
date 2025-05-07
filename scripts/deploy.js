const hre = require("hardhat");

async function main() {
  const CryptPicRegistry = await hre.ethers.getContractFactory("CryptPicRegistry");
  const registry = await CryptPicRegistry.deploy();
  await registry.deployed();

  console.log(`Contract deployed to: ${registry.address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
