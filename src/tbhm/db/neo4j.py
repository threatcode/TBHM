"""
Neo4j session configuration for asset relationship mapping.
"""

from neo4j import AsyncGraphDatabase, AsyncDriver

from ..core.config import settings


class Neo4jClient:
    """Neo4j database client for asset relationships."""

    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        self._driver: AsyncDriver = None

    async def connect(self) -> AsyncDriver:
        """Connect to Neo4j database."""
        if self._driver is None:
            self._driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password)
            )
        return self._driver

    async def close(self):
        """Close Neo4j connection."""
        if self._driver:
            await self._driver.close()
            self._driver = None

    async def verify_connectivity(self) -> bool:
        """Verify Neo4j connection."""
        try:
            driver = await self.connect()
            async with driver.session() as session:
                await session.run("RETURN 1")
            return True
        except Exception:
            return False

    async def execute_query(self, query: str, parameters: dict = None):
        """Execute a Cypher query."""
        driver = await self.connect()
        async with driver.session() as session:
            result = await session.run(query, parameters or {})
            return await result.data()

    async def create_asset_relationships(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: dict = None
    ):
        """Create a relationship between two assets."""
        query = f"""
        MATCH (a {{id: $source_id}})
        MATCH (b {{id: $target_id}})
        CREATE (a)-[r:{rel_type}]->(b)
        SET r = $properties
        RETURN a, r, b
        """
        return await self.execute_query(
            query,
            {"source_id": source_id, "target_id": target_id, "properties": properties or {}}
        )


neo4j_client = Neo4jClient()