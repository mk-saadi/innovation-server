const express = require("express");
const app = express();
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const port = process.env.PORT || 9100;

// middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
	const authorization = req.headers.authorization;
	if (!authorization) {
		return res
			.status(401)
			.send({ error: true, message: "unauthorized access" });
	}
	const token = authorization.split(" ")[1];

	jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
		if (err) {
			return res
				.status(401)
				.send({ error: true, message: "unauthorized access" });
		}
		req.decoded = decoded;
		next();
	});
};

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `${process.env.Mongo_URI}`;

const client = new MongoClient(uri, {
	serverApi: {
		version: ServerApiVersion.v1,
		strict: true,
		deprecationErrors: true,
	},
});

async function run() {
	try {
		const usersCollection = client.db("innovationBD").collection("users");
		const productsCollection = client
			.db("innovationBD")
			.collection("products");

		app.post("/jwt", (req, res) => {
			const user = req.body;
			const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
				expiresIn: "7d",
			});

			res.send({ token });
		});

		const verifyAdmin = async (req, res, next) => {
			const email = req.decoded.email;
			const query = { email: email };
			const user = await usersCollection.findOne(query);
			if (user?.role !== "admin") {
				return res
					.status(403)
					.send({ error: true, message: "forbidden access!" });
			}
			next();
		};

		// >> users api
		app.get("/users", async (req, res) => {
			let query = {};

			if (req.query?.email) {
				query.email = {
					$regex: req.query.email,
					$options: "i",
				};
			}

			if (req.query?.name) {
				query.name = { $regex: req.query.name, $options: "i" };
			}

			if (req.query?.role) {
				query.role = { $regex: req.query.role, $options: "i" };
			}

			const result = await usersCollection.find(query).toArray();
			res.send(result);
		});

		app.get("/users/:role/:email", verifyJWT, async (req, res) => {
			const role = req.params.role;
			const email = req.params.email;

			if (email !== req.decoded.email) {
				return res.send({ [role]: false });
			}

			const query = { email: email };
			const user = await usersCollection.findOne(query);
			const result = { [role]: user?.role === role };
			res.send(result);
		});

		app.patch("/users/:email", verifyJWT, verifyAdmin, async (req, res) => {
			const { email } = req.params;
			const { role } = req.body;

			try {
				await usersCollection.updateOne(
					{ email: email },
					{ $set: { role: role } }
				);

				res.status(200).send({
					message: "User role updated successfully",
				});
			} catch (error) {
				res.status(500).send({
					error: "Internal server error",
				});
			}
		});

		app.post("/users", async (req, res) => {
			const user = req.body;
			const query = { email: user.email };
			console.log("query: ", query);
			const existingUser = await usersCollection.findOne(query);

			if (existingUser) {
				return res.send({ message: "user already exists" });
			}

			const result = await usersCollection.insertOne(user);
			res.send(result);
		});

		app.delete("/users/:id", verifyJWT, async (req, res) => {
			const id = req.params.id;
			const query = { _id: new ObjectId(id) };
			const result = await usersCollection.deleteOne(query);
			res.send(result);
		});

		// >> products api
		app.post("/products", async (req, res) => {
			const products = req.body;
			products.createdAt = new Date();
			const result = await productsCollection.insertOne(products);
			res.send(result);
		});

		app.get("/products", async (req, res) => {
			const result = await productsCollection.find().toArray();
			res.send(result);
		});

		app.get("/products/:id", async (req, res) => {
			const id = req.params.id;
			try {
				const queryWithObjectId = { _id: new ObjectId(id) };
				const result = await productsCollection.findOne(
					queryWithObjectId
				);

				if (!result) {
					const queryWithoutObjectId = { _id: id };
					const fallbackResult = await productsCollection.findOne(
						queryWithoutObjectId
					);

					if (!fallbackResult) {
						res.status(404).send("Product not found");
						return;
					}

					res.send(fallbackResult);
					return;
				}

				res.send(result);
			} catch (error) {
				res.status(500).send("Internal Server Error");
			}
		});

		await client.db("admin").command({ ping: 1 });
		console.log(
			"Pinged your deployment. You are successfully connected to MongoDB!"
		);
	} finally {
	}
}
run().catch(console.dir);

app.get("/", (req, res) => {
	res.send("Innovation server is running!");
});

app.listen(port, () => {
	console.log(`Innovation server is live on port ${port}`);
});
