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
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Link,
  Alert
} from '@mui/material';
import { FixedSizeList } from 'react-window';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import VulnerabilityCard from './Vuln';
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
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [vulnerabilityDialogOpen, setVulnerabilityDialogOpen] = useState(false);

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

  const handleVulnerabilityClick = (vulnerability) => {
    setSelectedVulnerability(vulnerability);
    setVulnerabilityDialogOpen(true);
  };

  const handleCloseVulnerabilityDialog = () => {
    setVulnerabilityDialogOpen(false);
    setSelectedVulnerability(null);
  };

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
              Vulnerabilities ({device.vulnerabilities ? device.vulnerabilities.length : 0})
            </Typography>
            {device.vulnerabilities && device.vulnerabilities.length > 0 ? (
              <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                {device.vulnerabilities.map((vulnerability, index) => (
                  <Card 
                    key={index} 
                    variant="outlined" 
                    sx={{ 
                      mb: 1, 
                      cursor: 'pointer',
                      '&:hover': { 
                        backgroundColor: 'action.hover',
                        boxShadow: 1
                      }
                    }}
                    onClick={() => handleVulnerabilityClick(vulnerability)}
                  >
                    <CardContent sx={{ py: 1.5, px: 2 }}>
                      <Box display="flex" alignItems="center" justifyContent="space-between">
                        <Box>
                          <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
                            {vulnerability.service} on {vulnerability.port}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {vulnerability.product} {vulnerability.version}
                          </Typography>
                          <Box display="flex" gap={1} mt={1}>
                            {vulnerability.cpes && vulnerability.cpes.slice(0, 3).map((cpe, cpeIndex) => (
                              <Chip
                                key={cpeIndex}
                                label={cpe.id}
                                size="small"
                                color={parseFloat(cpe.cvss) >= 7.0 ? 'error' : parseFloat(cpe.cvss) >= 4.0 ? 'warning' : 'default'}
                                variant="outlined"
                              />
                            ))}
                            {vulnerability.cpes && vulnerability.cpes.length > 3 && (
                              <Chip
                                label={`+${vulnerability.cpes.length - 3} more`}
                                size="small"
                                variant="outlined"
                              />
                            )}
                          </Box>
                        </Box>
                        <SecurityIcon color="error" />
                      </Box>
                    </CardContent>
                  </Card>
                ))}
              </Box>
            ) : (
              <Alert severity="info">
                No vulnerabilities found for this device.
              </Alert>
            )}
          </Grid>
        </Grid>
      </CardContent>
      
      {/* Vulnerability Details Dialog */}
      {selectedVulnerability && (
        <VulnerabilityCard
          vulnerability={selectedVulnerability}
          open={vulnerabilityDialogOpen}
          onClose={handleCloseVulnerabilityDialog}
        />
      )}
    </Card>
  );
};

export default Device;
