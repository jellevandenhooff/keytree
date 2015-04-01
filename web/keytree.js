var React = require('react/addons');

var $ = require('jquery');
var crypto = require('./crypto');

var downloadJson = function(url) {
  return Promise.resolve($.ajax(url, {dataType: 'json'}));
}

var Lookup = React.createClass({
  mixins: [React.addons.LinkedStateMixin],
  fetch: async function(name) {
    this.setState({loading: true});
    try {
      var data = await downloadJson("/keytree/lookup?name=" + name);
      this.setState({loading: false, result: data});
    } catch (e) {
      this.setState({result: undefined, loading: false});
    }
  },
  componentDidMount: function() {
    this.fetch(this.state.name);
  },
  getInitialState: function() {
    return {name: 'email:jelle@vandenhooff.name', loading: true};
  },
  handleLookup: function(e) {
    e.preventDefault();
    this.fetch(this.state.name);
  },
  render: function() {
    return (
      <div>
        <h1>Lookup</h1>
        <form className="input-group" onSubmit={this.handleLookup}>
          <input type="text" className="form-control" valueLink={this.linkState('name')} />
          <span className="input-group-btn">
            <button id="lookup-submit-btn" className="btn btn-primary" type="submit" 
                disabled={this.state.loading ? 'disabled' : null}>
                {this.state.loading ? 'Loading...' : 'Lookup'}
            </button>
          </span>
        </form>
        {this.state.result ?
          <pre>{JSON.stringify(this.state.result.Entry, null, "  ")}</pre> : null
        }
      </div>
    );
  }
});

var Browser = React.createClass({
  fetch: async function(after) {
    this.setState({loading: true});
    try {
      var data;
      if (after !== undefined) {
        data = await downloadJson("/keytree/browse?name=" + after);
      } else {
        data = await downloadJson("/keytree/browse");
      }
      if (data === null) {
        if (after !== undefined) {
          this.fetch();
        }
        return;
      }
      this.setState({loading: false, records: data});
    } catch (e) {
      this.setState({loading: false});
    }
  },
  componentDidMount: function() {
    this.fetch();
  },
  getInitialState: function() {
    return {records: [], loading: true};
  },
  handleNext: function(e) {
    e.preventDefault();
    var after = undefined;
    if (this.state.records.length > 0) {
      after = this.state.records[this.state.records.length - 1].Name;
    }
    this.fetch(after);
  },
  render: function() {
    var list = (
      <ul>
        {this.state.records.map((record) => 
          <li key={record.Name}>{record.Name}</li>)}
      </ul>
    );

    return (
      <div>
        <h1>Browse</h1>
        {list}
        {this.state.loading ?
          <span>Loading...</span> : 
          <a onClick={this.handleNext}>More...</a>}
      </div>
    );
  }
});

var App = React.createClass({
  render: function() {
    return (
      <div>
        <Lookup />
        <Browser />
      </div>
    );
  }
});

window.runApp = function() {
  React.render(<App />, document.getElementById('container'));
}
