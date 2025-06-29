import React, { useState, useEffect } from "react";
import { 
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import api from "../services/api";
import DeviceNode from "./DeviceNode";

const Network = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const fetchNetwork = async () => {
      try {
        const response = await api.get('/network');
        const clients = response.data.clients;
        const router = response.data.router;

        // Create nodes
        const nodes = [...clients, router].map((device) => ({
          id: device.ip,
          type: 'custom',
          data: { 
            label: device.hostname,
            device: device,
            type: router.ip === device.ip ? 'target' : 'source'
           },
          position: {
            x: Math.random() * 1000,
            y: Math.random() * 1000
          }
        }));

        console.table(nodes);

        setNodes(nodes);

        // Create edges
        const edges = clients.map((client) => ({
          id: `${client.ip}-${router.ip}`,
          source: client.ip,
          target: router.ip
        }));

        console.table(edges);

        setEdges(edges);
      } catch (error) {
        console.error('Error fetching network:', error);
      }
    };

    fetchNetwork();
  }, []); // Empty dependency array ensures this effect runs only once on mount

  return (
    <div style={{ width: '100vw', height: '100vh' }}>
      <ReactFlow 
        nodes={nodes} nodeTypes={{ custom: DeviceNode }} onNodesChange={onNodesChange}
        edges={edges} onEdgesChange={onEdgesChange}
        fitView>
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  );
};

export default Network;
