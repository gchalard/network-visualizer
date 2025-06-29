import React, { useEffect, useState } from 'react';
import { useParams, useLocation } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Grid,
  Divider,
  CircularProgress,
  Box,
  Stack,
  ListItem,
  ListItemText
} from '@mui/material';
import { FixedSizeList } from 'react-window';
import api from "../services/api";

const renderRow = (props, items) => {
  const { index, style } = props;

  return (
    <ListItem style={style} key={index} component="div" disablePadding>
        <ListItemText primary={`${items[index]}`} />
    </ListItem>
  );
};

const VirtualizedList = ({ items }) => {
  const RenderRow = (props) => renderRow(props, items);

  return (
    <Box sx={{ width: '100%', height: 400, maxWidth: 360, bgcolor: 'background.paper' }}>
      <FixedSizeList
        height={400}
        width={360}
        itemSize={46}
        itemCount={items.length}
        overscanCount={5}
      >
        {RenderRow}
      </FixedSizeList>
    </Box>
  );
};

const Device = () => {
  const { id } = useParams(); // Get the device ID from the URL
  const { state } = useLocation(); // Get the state passed from navigation
  const [device, setDevice] = useState(state?.nodeData || null);
  const [loading, setLoading] = useState(!state?.nodeData); // Set loading based on whether data is already available

  useEffect(() => {
    const fetchDeviceDetails = async () => {
      try {
        setLoading(true);
        const response = await api.get(`/devices/${id}`); // Replace with your actual API endpoint
        setDevice(response.data);
      } catch (error) {
        console.error('Error fetching device details:', error);
      } finally {
        setLoading(false);
      }
    };

    if (!state?.nodeData) {
      fetchDeviceDetails();
    }
  }, [id, state?.nodeData]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  if (!device) {
    return <Typography variant="h6">No device data available</Typography>;
  }

  return (
    <Card>
      <CardContent>
        <Typography variant="h4" gutterBottom>
          {device.hostname}
        </Typography>
        <Divider sx={{ my: 2 }} />
        <Grid container spacing={2}>
            <Stack direction={"row"} spacing={2} 
                sx={{
                    justifyContent: "center",
                    alignItems: "center",
                }}
            >
                {Object.keys(device).filter((k) => k !== "ports" && k !== "vulnerabilities" && k !== "hops").map((key) => (
                <Grid item size={12/Object.keys(device).filter((k) => k !== "ports" && k !== "vulnerabilities" && k !== "hops" && device[k] !== null).length} key={key}>
                    <Typography variant="body1"><strong>{key.replace(/_/g, ' ').toUpperCase()}:</strong> {device[key]}</Typography>
                </Grid>
                ))}
            </Stack>

          <Grid item size={6}>
            
            <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
              Open Ports
            </Typography>
            {device.ports ? (
              <VirtualizedList items={device.ports} />
            ) : (
              <Typography variant="body2">No open ports data available</Typography>
            )}
          </Grid>
          <Grid item size={6}>
            <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
              Vulnerabilities
            </Typography>
            {device.vulnerabilities ? (
              <VirtualizedList items={device.vulnerabilities} />
            ) : (
              <Typography variant="body2">No vulnerabilities data available</Typography>
            )}
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
};

export default Device;
