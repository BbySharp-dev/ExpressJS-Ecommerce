const socketIo = require("socket.io");
const dotenv = require("dotenv");
dotenv.config()

let io;

function initialize(server) {
  io = socketIo(server,{
    cors: {
      origin: process.env.URL_FE_APP,
      methods: ["GET", "POST", "PUT", "DELETE"]
    }
  });

  io.on("connection", (socket) => {
    console.log("New client connected");
  });
}

function getIo() {
  if (!io) {
    return
  }
  return io;
}

module.exports = {
  initialize,
  getIo,
};