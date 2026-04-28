import express from "express"; 
import cors from "cors"; 
const app = express(); 
app.use(cors()); 
app.get("/", (req, res) => { 
res.send("Tesla backend running"); 
}); 
app.get("/health", (req, res) => { 
res.json({ status: "ok" }); 
}); 
const PORT = process.env.PORT || 8080; 
app.listen(PORT, () => { 
console.log("Server running on port", PORT); 
}); 

 

 
