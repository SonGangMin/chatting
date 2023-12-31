const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const userRoutes = require("./routes/userRoutes");
const app = express();
require("dotenv").config();

app.use(cors());
app.use(express.json());

app.use("/api/auth", userRoutes);

mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("몽고DB 연결 성공");
  })
  .catch((error) => {
    console.log(error.message);
  });

const port = 5000;
const server = app.listen(port, () => {
  console.log(`Server Started on PORT ${port}`);
});
