import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import './App.css'
import Network from './components/Network'
import Device from './components/Device'

function App() {

  return (
    <Router>
      <Routes>
        <Route path="/" element={<Network />} />
        <Route path="/device/:ip" element={<Device />} />
      </Routes>
    </Router>
  )
}

export default App
