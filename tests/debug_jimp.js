const Jimp = require("jimp");
console.log("Type of Jimp:", typeof Jimp);
console.log("Keys of Jimp:", Object.keys(Jimp));
console.log("Is Jimp.read a function?", typeof Jimp.read);
if (Jimp.default) {
  console.log("Is Jimp.default.read a function?", typeof Jimp.default.read);
}
