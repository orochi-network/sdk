const fs = require('fs');

let abiFileContent = JSON.parse(
  fs.readFileSync(
    '/home/chiro/Github/smart-contracts/artifacts/contracts/orand-v2/OrandProviderV2.sol/OrandProviderV2.json',
    'utf8',
  ),
);
fs.writeFileSync('./src/abi/OrandProviderV2.json', JSON.stringify(abiFileContent.abi));

let fileContent = fs
  .readFileSync('/home/chiro/Github/smart-contracts/typechain-types/contracts/orand-v2/OrandProviderV2.ts', 'utf8')
  .replace('../../common', './common');
fs.writeFileSync('./src/types/OrandProviderV2.ts', fileContent);
